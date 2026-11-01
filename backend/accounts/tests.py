from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from unittest.mock import patch

from axes.models import AccessAttempt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import identify_hasher
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.core.management import call_command
from django.db import connections
from django.test import Client, RequestFactory, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.utils import timezone
from rest_framework.exceptions import Throttled

from vault.models import SecuritySettings, Vault
from .models import AccountSession, AuthRequestWindow
from .security import limit_requests
from .services import start_session


PASSWORD = "a test account passphrase 73!"


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False)
class AccountAPITests(TestCase):
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)

    def csrf(self, client=None):
        client = client or self.client
        response = client.get("/api/auth/session/")
        self.assertEqual(response.status_code, 200)
        return response.json()["csrfToken"]

    def post(self, path, data=None, *, client=None, token=None, **headers):
        client = client or self.client
        return client.post(f"/api/auth/{path}/", data or {}, content_type="application/json",
                           HTTP_X_CSRFTOKEN=token or self.csrf(client), **headers)

    def register(self, username="test-user", *, client=None):
        return self.post("register", {"username": username, "password": PASSWORD}, client=client)

    def test_bootstrap_returns_csrf_without_authenticating_and_is_not_cacheable(self):
        response = self.client.get("/api/auth/session/")
        self.assertIsNone(response.json()["user"])
        self.assertEqual(len(response.json()["csrfToken"]), 64)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertIn("Cookie", response["Vary"])
        self.assertTrue(response.cookies[settings.CSRF_COOKIE_NAME]["httponly"])
        self.assertEqual(Session.objects.count(), 0)

    def test_register_uses_django_password_hash_and_does_not_create_vault(self):
        response = self.register()
        self.assertEqual(response.status_code, 201)
        user = get_user_model().objects.get(username="test-user")
        self.assertTrue(user.check_password(PASSWORD))
        self.assertEqual(identify_hasher(user.password).algorithm, "pbkdf2_sha256")
        self.assertNotIn(PASSWORD, response.content.decode())
        self.assertTrue(SecuritySettings.objects.filter(user=user).exists())
        self.assertEqual(Vault.objects.count(), 0)
        self.assertEqual(AccountSession.objects.filter(user=user).count(), 1)
        cookie = response.cookies[settings.SESSION_COOKIE_NAME]
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")
        self.assertEqual(cookie["max-age"], "")

    def test_normalizes_username_and_preserves_password_whitespace(self):
        response = self.post("register", {"username": " Test-User ", "password": "  " + PASSWORD + "  "})
        self.assertEqual(response.status_code, 201)
        user = get_user_model().objects.get(username="test-user")
        self.assertTrue(user.check_password("  " + PASSWORD + "  "))
        self.assertFalse(user.check_password(PASSWORD))

    @override_settings(AUTH_REQUEST_LIMITS={"register": (20, 3600), "login": (30, 60)})
    def test_rejects_weak_password_unknown_fields_and_invalid_usernames(self):
        for data in (
            {"username": "test-user", "password": "short"},
            {"username": "test-user", "password": "123456789012"},
            {"username": "bad username", "password": PASSWORD},
            {"username": "test-user", "password": PASSWORD, "master_password": "must not be accepted"},
            {"username": "test-user", "password": PASSWORD, "is_staff": True},
            {"username": "test-user", "password": 123456789012},
            {"username": ["test-user"], "password": PASSWORD},
        ):
            with self.subTest(data=list(data)):
                response = self.post("register", data)
                self.assertEqual(response.status_code, 400)
                self.assertNotIn(PASSWORD, response.content.decode())
        self.assertEqual(get_user_model().objects.count(), 0)

    def test_every_mutation_requires_csrf_even_before_authentication(self):
        self.csrf()
        for path in ("register", "login", "logout"):
            with self.subTest(path=path):
                response = self.client.post(f"/api/auth/{path}/", {"username": "test-user", "password": PASSWORD}, content_type="application/json")
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.json()["code"], "csrf_failed")
        self.assertEqual(get_user_model().objects.count(), 0)

    def test_disallows_untrusted_origins_even_with_valid_csrf(self):
        response = self.post("register", {"username": "test-user", "password": PASSWORD}, HTTP_ORIGIN="https://evil.example")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(get_user_model().objects.count(), 0)

    def test_login_rotates_session_key_and_csrf_token(self):
        get_user_model().objects.create_user(username="test-user", password=PASSWORD)
        anonymous = self.client.session
        anonymous["before-login"] = True
        anonymous.save()
        old_key = anonymous.session_key
        old_token = self.csrf()
        response = self.post("login", {"username": "test-user", "password": PASSWORD}, token=old_token)
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json()["csrfToken"], old_token)
        self.assertNotEqual(self.client.cookies[settings.SESSION_COOKIE_NAME].value, old_key)
        self.assertFalse(Session.objects.filter(pk=old_key).exists())
        rejected = self.post("logout", token=old_token)
        self.assertEqual(rejected.status_code, 403)

    def test_wrong_unknown_and_inactive_accounts_have_the_same_error(self):
        get_user_model().objects.create_user(username="inactive", password=PASSWORD, is_active=False)
        responses = [self.post("login", {"username": username, "password": PASSWORD}) for username in ("unknown", "inactive")]
        self.assertEqual(responses[0].status_code, 400)
        self.assertEqual(responses[0].json(), responses[1].json())
        self.assertEqual(AccountSession.objects.count(), 0)

    def test_duplicate_registration_is_handled_without_partial_records(self):
        self.assertEqual(self.register().status_code, 201)
        other = Client(enforce_csrf_checks=True)
        response = self.register(client=other)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(get_user_model().objects.count(), 1)
        self.assertEqual(SecuritySettings.objects.count(), 1)

    def test_failed_session_creation_rolls_back_registration(self):
        with patch("accounts.services.start_session", side_effect=RuntimeError("test session failure")):
            with self.assertRaises(RuntimeError):
                self.register()
        self.assertEqual(get_user_model().objects.count(), 0)
        self.assertEqual(SecuritySettings.objects.count(), 0)
        self.assertEqual(AccountSession.objects.count(), 0)

    def test_logout_invalidates_the_database_session(self):
        self.register()
        key = self.client.cookies[settings.SESSION_COOKIE_NAME].value
        response = self.post("logout")
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.json()["user"])
        self.assertFalse(Session.objects.filter(pk=key).exists())
        self.assertEqual(AccountSession.objects.count(), 0)
        self.assertIsNone(self.client.get("/api/auth/session/").json()["user"])

    def test_sessions_require_authentication_and_never_expose_bearer_keys(self):
        self.assertEqual(self.client.get("/api/auth/sessions/").status_code, 403)
        self.register()
        response = self.client.get("/api/auth/sessions/")
        row = response.json()["sessions"][0]
        self.assertTrue(row["current"])
        self.assertNotIn(self.client.cookies[settings.SESSION_COOKIE_NAME].value, response.content.decode())
        self.assertEqual(set(row), {"id", "createdAt", "expiresAt", "current"})

    def test_revoke_other_browser_session_and_enforce_ownership(self):
        self.register()
        second = Client(enforce_csrf_checks=True)
        self.post("login", {"username": "test-user", "password": PASSWORD}, client=second)
        sessions = self.client.get("/api/auth/sessions/").json()["sessions"]
        target = next(row for row in sessions if not row["current"])
        attacker = Client(enforce_csrf_checks=True)
        self.register(username="another-user", client=attacker)
        response = attacker.delete(f"/api/auth/sessions/{target['id']}/", HTTP_X_CSRFTOKEN=self.csrf(attacker))
        self.assertEqual(response.status_code, 404)
        response = self.client.delete(f"/api/auth/sessions/{target['id']}/", HTTP_X_CSRFTOKEN=self.csrf())
        self.assertEqual(response.status_code, 204)
        self.assertIsNone(second.get("/api/auth/session/").json()["user"])
        self.assertIsNotNone(self.client.get("/api/auth/session/").json()["user"])

    def test_revoke_current_session_and_csrf_requirement(self):
        self.register()
        target = self.client.get("/api/auth/sessions/").json()["sessions"][0]["id"]
        self.assertEqual(self.client.delete(f"/api/auth/sessions/{target}/").status_code, 403)
        self.assertEqual(self.client.delete(f"/api/auth/sessions/{target}/", HTTP_X_CSRFTOKEN=self.csrf()).status_code, 204)
        self.assertIsNone(self.client.get("/api/auth/session/").json()["user"])

    def test_expired_session_is_not_authenticated(self):
        self.register()
        Session.objects.update(expire_date=timezone.now() - timedelta(seconds=1))
        self.assertIsNone(self.client.get("/api/auth/session/").json()["user"])
        self.assertEqual(self.client.get("/api/auth/sessions/").status_code, 403)

    @override_settings(AXES_FAILURE_LIMIT=3)
    def test_lockout_blocks_correct_password_and_ignores_forged_forwarded_ip(self):
        get_user_model().objects.create_user(username="test-user", password=PASSWORD)
        for _ in range(3):
            self.post("login", {"username": "test-user", "password": "wrong"})
        response = self.post("login", {"username": "test-user", "password": PASSWORD}, HTTP_X_FORWARDED_FOR="203.0.113.99")
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response)
        self.assertEqual(AccountSession.objects.count(), 0)
        self.assertNotIn(PASSWORD, str(list(AccessAttempt.objects.values())))

    @override_settings(AXES_FAILURE_LIMIT=2)
    def test_account_lockout_applies_across_client_ips(self):
        get_user_model().objects.create_user(username="test-user", password=PASSWORD)
        for ip in ("192.0.2.1", "192.0.2.2"):
            self.post("login", {"username": "test-user", "password": "wrong"}, REMOTE_ADDR=ip)
        response = self.post("login", {"username": "test-user", "password": PASSWORD}, REMOTE_ADDR="192.0.2.3")
        self.assertEqual(response.status_code, 429)

    @override_settings(AXES_FAILURE_LIMIT=2)
    def test_admin_login_uses_the_same_brute_force_protection(self):
        for _ in range(2):
            self.client.post("/admin/login/", {"username": "staff-user", "password": "wrong"}, HTTP_X_CSRFTOKEN=self.csrf())
        response = self.client.post("/admin/login/", {"username": "staff-user", "password": "wrong"}, HTTP_X_CSRFTOKEN=self.csrf())
        self.assertEqual(response.status_code, 429)
        self.assertNotIn("wrong", str(list(AccessAttempt.objects.values_list("post_data", flat=True))))

    @override_settings(AUTH_REQUEST_LIMITS={"register": (1, 3600), "login": (1, 60)})
    def test_request_budgets_count_invalid_bodies_and_are_database_backed(self):
        for path in ("register", "login"):
            with self.subTest(path=path):
                self.assertEqual(self.post(path, {"unexpected": "field"}).status_code, 400)
                self.assertEqual(self.post(path, {"unexpected": "field"}).status_code, 429)
        self.assertEqual(AuthRequestWindow.objects.count(), 2)
        self.assertNotIn("127.0.0.1", str(list(AuthRequestWindow.objects.values())))

    def test_safe_methods_do_not_perform_account_mutations(self):
        for path in ("register", "login", "logout"):
            with self.subTest(path=path):
                self.assertIn(self.client.get(f"/api/auth/{path}/").status_code, (403, 405))
        self.assertEqual(get_user_model().objects.count(), 0)

    @override_settings(SESSION_COOKIE_SECURE=True, CSRF_COOKIE_SECURE=True)
    def test_https_cookies_are_secure(self):
        self.assertTrue(self.client.get("/api/auth/session/", secure=True).cookies[settings.CSRF_COOKIE_NAME]["secure"])
        response = self.register()
        self.assertTrue(response.cookies[settings.SESSION_COOKIE_NAME]["secure"])


class RequestBudgetTests(TestCase):
    @override_settings(AUTH_REQUEST_LIMITS={"register": (1, 60)})
    def test_budget_expires_and_does_not_slide_when_requests_are_blocked(self):
        request = RequestFactory().post("/")
        now = timezone.now().replace(second=0, microsecond=0)
        with patch("accounts.security.timezone.now", return_value=now):
            limit_requests(request, "register")
            with self.assertRaises(Throttled):
                limit_requests(request, "register")
        with patch("accounts.security.timezone.now", return_value=now + timedelta(minutes=1)):
            limit_requests(request, "register")
        self.assertEqual(AuthRequestWindow.objects.count(), 2)

    def test_sign_in_cap_preserves_current_session_and_revokes_oldest(self):
        user = get_user_model().objects.create_user(username="session-cap")
        keys = []
        for _ in range(11):
            request = RequestFactory().post("/")
            request.session = SessionStore()
            start_session(request, user)
            keys.append(request.session.session_key)
        self.assertFalse(Session.objects.filter(pk=keys[0]).exists())
        self.assertTrue(Session.objects.filter(pk=keys[-1]).exists())
        self.assertEqual(AccountSession.objects.filter(user=user).count(), 10)

    def test_cleanup_removes_only_expired_auth_state(self):
        from io import StringIO
        now = timezone.now()
        AuthRequestWindow.objects.create(key="expired", expires_at=now - timedelta(seconds=1))
        AuthRequestWindow.objects.create(key="active", expires_at=now + timedelta(minutes=1))
        Session.objects.create(session_key="expired-session", session_data="", expire_date=now - timedelta(seconds=1))
        Session.objects.create(session_key="active-session", session_data="", expire_date=now + timedelta(minutes=1))
        call_command("prune_auth_state", stdout=StringIO())
        self.assertEqual(list(AuthRequestWindow.objects.values_list("key", flat=True)), ["active"])
        self.assertEqual(list(Session.objects.values_list("session_key", flat=True)), ["active-session"])


class ConcurrentRequestBudgetTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    @override_settings(AUTH_REQUEST_LIMITS={"register": (1, 3600)})
    def test_concurrent_workers_cannot_exceed_budget(self):
        barrier = Barrier(2)

        def attempt(_):
            try:
                request = RequestFactory().post("/")
                barrier.wait(timeout=10)
                try:
                    limit_requests(request, "register")
                    return "allowed"
                except Throttled:
                    return "blocked"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(attempt, range(2)))
        self.assertCountEqual(results, ["allowed", "blocked"])
