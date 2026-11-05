from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core import mail
from django.core.management import call_command
from django.db import connections
from django.test import Client, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.utils import timezone

from vault.models import Vault

from .models import AccountSession, PasswordResetRequest, RecoveryEmail
from .recovery import (InvalidRecoveryLink, dispatch_reset_requests, reset_account_password,
                       reset_tokens, verification_tokens)


PASSWORD = "Public Account Passphrase 36!"
NEW_PASSWORD = "Public Replacement Phrase 61!"
EMAIL = "recovery@example.test"
BASE = "/api/auth/recovery/"


def post(client, path, data):
    csrf = client.get("/api/auth/session/").json()["csrfToken"]
    return client.post(path, data, content_type="application/json", HTTP_X_CSRFTOKEN=csrf)


def emailed_link(action, username, recipient=EMAIL):
    message = mail.outbox[-1]
    assert message.to == [recipient]
    url = urlsplit(next(line for line in message.body.splitlines() if line.startswith("https://")))
    assert (url.netloc, url.path, url.query) == ("vault.example.test", "/", "")
    data = {key: values[0] for key, values in parse_qs(url.fragment).items()}
    assert data.pop("account-action") == action
    assert data["username"] == username
    return data


@override_settings(
    ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False,
    ACCOUNT_LINK_ORIGIN="https://vault.example.test",
    MAILERS={"default": {"BACKEND": "django.core.mail.backends.locmem.EmailBackend"}},
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
)
class AccountRecoveryTests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(username="recovery-owner", password=PASSWORD)
        self.owner_client = Client(enforce_csrf_checks=True)
        self.guest = Client(enforce_csrf_checks=True)
        self.assertEqual(post(self.owner_client, "/api/auth/login/", {"username": self.owner.username, "password": PASSWORD}).status_code, 200)

    def enroll(self, email=EMAIL, password=PASSWORD):
        return post(self.owner_client, BASE + "email/", {"email": email, "password": password})

    def confirmed_address(self):
        return RecoveryEmail.objects.create(user=self.owner, email=EMAIL, verified_at=timezone.now())

    def test_enrollment_requires_authentication_password_and_csrf(self):
        self.assertEqual(self.guest.get(BASE + "email/").status_code, 403)
        self.assertEqual(post(self.guest, BASE + "email/", {"email": EMAIL, "password": PASSWORD}).status_code, 403)
        self.assertEqual(self.owner_client.post(BASE + "email/", {"email": EMAIL, "password": PASSWORD}, content_type="application/json").status_code, 403)
        self.assertEqual(self.enroll(password="incorrect").status_code, 400)
        self.assertFalse(RecoveryEmail.objects.exists())
        self.assertEqual(mail.outbox, [])

    def test_verification_link_is_bound_to_address_and_consumed_once(self):
        self.assertEqual(self.enroll().status_code, 204)
        link = emailed_link("verify", self.owner.username)
        newer_email = "new-recovery@example.test"
        self.assertEqual(self.enroll(email=newer_email).status_code, 204)
        new_link = emailed_link("verify", self.owner.username, newer_email)
        self.assertEqual(post(self.guest, BASE + "verify/", link).status_code, 400)
        self.assertEqual(post(self.guest, BASE + "reset/", {**new_link, "password": NEW_PASSWORD}).status_code, 400)
        self.assertEqual(self.guest.get(BASE + "verify/").status_code, 405)
        self.assertEqual(post(self.guest, BASE + "verify/", new_link).status_code, 204)
        self.assertEqual(post(self.guest, BASE + "verify/", new_link).status_code, 400)
        response = self.owner_client.get(BASE + "email/")
        self.assertEqual(response.json(), {"email": newer_email, "verified": True})
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(self.enroll().status_code, 409)
        self.assertEqual(RecoveryEmail.objects.get(user=self.owner).email, newer_email)
        self.assertIsNone(self.guest.get("/api/auth/session/").json()["user"])

    def test_reset_requests_have_identical_responses_and_queue_for_all_usernames(self):
        self.confirmed_address()
        pending = get_user_model().objects.create_user(username="unverified-owner", password=PASSWORD)
        RecoveryEmail.objects.create(user=pending, email="unverified@example.test")
        inactive = get_user_model().objects.create_user(username="inactive-owner", password=PASSWORD, is_active=False)
        RecoveryEmail.objects.create(user=inactive, email="inactive@example.test", verified_at=timezone.now())
        for name in (self.owner.username, pending.username, inactive.username, "unknown-owner"):
            response = post(self.guest, BASE + "request/", {"username": name})
            self.assertEqual((response.status_code, response.json()), (202, {"accepted": True}))
        self.assertEqual(PasswordResetRequest.objects.count(), 4)
        self.assertEqual(mail.outbox, [])
        call_command("dispatch_account_recovery", verbosity=0)
        self.assertEqual(len(mail.outbox), 1)
        emailed_link("reset", self.owner.username)
        self.assertFalse(PasswordResetRequest.objects.exists())

    def test_password_reset_revokes_all_sessions_preserves_vault_and_requires_sign_in(self):
        self.confirmed_address()
        vault = Vault.objects.create(
            owner=self.owner, kdf_salt="AAAAAAAAAAAAAAAAAAAAAA==", wrap_nonce="AAAAAAAAAAAAAAAA",
            wrapped_key="A" * 64,
        )
        snapshot = Vault.objects.filter(pk=vault.pk).values().get()
        other = Client(enforce_csrf_checks=True)
        self.assertEqual(post(other, "/api/auth/login/", {"username": self.owner.username, "password": PASSWORD}).status_code, 200)
        previous_sessions = list(AccountSession.objects.filter(user=self.owner).values_list("session_id", flat=True))
        self.assertEqual(len(previous_sessions), 2)
        self.assertEqual(post(self.guest, BASE + "request/", {"username": self.owner.username}).status_code, 202)
        self.assertEqual(dispatch_reset_requests(), (1, 0))
        link = emailed_link("reset", self.owner.username)
        self.assertEqual(post(self.guest, BASE + "reset/", {**link, "password": "short"}).status_code, 400)
        self.assertEqual(self.guest.post(BASE + "reset/", {**link, "password": NEW_PASSWORD}, content_type="application/json").status_code, 403)
        self.assertEqual(post(self.guest, BASE + "reset/", {**link, "password": NEW_PASSWORD}).status_code, 204)
        self.assertEqual(post(self.guest, BASE + "reset/", {**link, "password": PASSWORD}).status_code, 400)
        self.assertFalse(Session.objects.filter(pk__in=previous_sessions).exists())
        self.assertEqual(Vault.objects.filter(pk=vault.pk).values().get(), snapshot)
        self.assertIsNone(self.guest.get("/api/auth/session/").json()["user"])
        self.assertIsNone(self.owner_client.get("/api/auth/session/").json()["user"])
        self.assertEqual(post(self.guest, "/api/auth/login/", {"username": self.owner.username, "password": PASSWORD}).status_code, 400)
        self.assertEqual(post(self.guest, "/api/auth/login/", {"username": self.owner.username, "password": NEW_PASSWORD}).status_code, 200)

    def test_expired_links_and_outdated_queue_jobs_are_rejected(self):
        self.assertEqual(self.enroll().status_code, 204)
        link = emailed_link("verify", self.owner.username)
        with patch.object(verification_tokens, "_now", return_value=verification_tokens._now() + timedelta(hours=1)):
            self.assertEqual(post(self.guest, BASE + "verify/", link).status_code, 400)
        self.assertEqual(post(self.guest, BASE + "verify/", link).status_code, 204)
        user = get_user_model().objects.get(pk=self.owner.pk)
        reset = {"username": user.username, "token": reset_tokens.make_token(user), "password": NEW_PASSWORD}
        with patch.object(reset_tokens, "_now", return_value=reset_tokens._now() + timedelta(hours=1)):
            self.assertEqual(post(self.guest, BASE + "reset/", reset).status_code, 400)
        self.assertEqual(post(self.guest, BASE + "request/", {"username": user.username}).status_code, 202)
        PasswordResetRequest.objects.update(created_at=timezone.now() - timedelta(hours=1))
        self.assertEqual(dispatch_reset_requests(), (0, 0))
        self.assertFalse(PasswordResetRequest.objects.exists())

    def test_per_username_budget_suppresses_extra_email_without_changing_response(self):
        self.confirmed_address()
        for index in range(4):
            response = post(self.guest, BASE + "request/", {"username": f" {self.owner.username.upper()} "})
            self.assertEqual((response.status_code, response.json()), (202, {"accepted": True}))
            self.assertEqual(dispatch_reset_requests(), (int(index < 3), 0))
        self.assertEqual(len(mail.outbox), 3)

    @override_settings(PRODUCTION=True, ACCOUNT_LINK_ORIGIN="http://localhost:5173")
    def test_unsafe_link_origin_cannot_send_or_enroll(self):
        self.assertEqual(self.enroll().status_code, 503)
        self.assertFalse(RecoveryEmail.objects.exists())
        self.assertEqual(mail.outbox, [])


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class ConcurrentPasswordResetTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_redemptions_of_one_link_only_change_password_once(self):
        owner = get_user_model().objects.create_user(username="recovery-race", password=PASSWORD)
        owner.recovery_email = RecoveryEmail.objects.create(user=owner, email=EMAIL, verified_at=timezone.now())
        token = reset_tokens.make_token(owner)
        barrier = Barrier(2)

        def redeem(password):
            try:
                barrier.wait(timeout=10)
                reset_account_password(username=owner.username, token=token, password=password)
                return password
            except InvalidRecoveryLink:
                return None
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(redeem, [NEW_PASSWORD, "Different Public Phrase 57!"]))
        winner, = [password for password in results if password is not None]
        owner.refresh_from_db()
        self.assertTrue(owner.check_password(winner))
