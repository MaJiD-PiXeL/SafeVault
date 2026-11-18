import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

from django.contrib.auth import get_user_model
from django.db import connections
from django.test import Client, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.utils import timezone

from . import mfa
from .models import RecoveryEmail, SecondFactor
from .recovery import reset_account_password, reset_tokens
from . import tests as account_tests
from .tests import PASSWORD


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False,
                   PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class SecondFactorTests(TestCase):
    csrf = account_tests.AccountAPITests.csrf
    post = account_tests.AccountAPITests.post

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.user = get_user_model().objects.create_user(username="mfa-user", password=PASSWORD)
        self.client.force_login(self.user)

    def enroll(self):
        setup = self.post("mfa", {"action": "begin", "password": PASSWORD})
        self.assertEqual(setup.status_code, 200)
        self.secret = setup.json()["secret"]
        self.counter = int(timezone.now().timestamp()) // 30
        response = self.post("mfa", {"action": "confirm", "password": PASSWORD, "code": mfa.hotp(self.secret, self.counter)})
        self.assertEqual(response.status_code, 200)
        return response.json()["recoveryCodes"]

    def test_rfc6238_sha1_vectors(self):
        secret = base64.b32encode(b"12345678901234567890").decode()
        for timestamp, expected in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                                    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]:
            self.assertEqual(mfa.hotp(secret, timestamp // 30, digits=8), expected)

    def test_enrollment_encrypts_seed_and_hashes_recovery_codes(self):
        codes = self.enroll()
        factor = SecondFactor.objects.get(user=self.user)
        self.assertNotIn(self.secret, factor.encrypted_secret)
        self.assertEqual(len(codes), 10)
        self.assertEqual(len(factor.recovery_hashes), 10)
        self.assertNotIn(codes[0].replace("-", ""), str(factor.recovery_hashes))
        status = self.client.get("/api/auth/mfa/")
        self.assertEqual(status.json(), {"enabled": True, "recoveryCodesRemaining": 10})
        self.assertEqual(status["Cache-Control"], "no-store")
        self.assertNotIn(self.secret, status.content.decode())

    def test_password_alone_and_replayed_codes_never_start_a_session(self):
        self.enroll()
        self.client.logout()
        payload = {"username": self.user.username, "password": PASSWORD}
        for code in ("", "000000", mfa.hotp(self.secret, self.counter)):
            response = self.post("login", {**payload, "code": code})
            self.assertEqual(response.status_code, 400)
            self.assertIsNone(self.client.get("/api/auth/session/").json()["user"])
        factor = SecondFactor.objects.get(user=self.user)
        factor.last_counter = self.counter - 1
        factor.save()
        response = self.post("login", {**payload, "code": mfa.hotp(self.secret, self.counter)})
        self.assertEqual(response.status_code, 200)
        self.client.logout()
        self.assertEqual(self.post("login", {**payload, "code": mfa.hotp(self.secret, self.counter)}).status_code, 400)

    def test_recovery_code_is_one_use_and_password_reset_does_not_remove_factor(self):
        codes = self.enroll()
        self.client.logout()
        payload = {"username": self.user.username, "password": PASSWORD, "code": codes[0]}
        self.assertEqual(self.post("login", payload).status_code, 200)
        self.client.logout()
        self.assertEqual(self.post("login", payload).status_code, 400)
        RecoveryEmail.objects.create(user=self.user, email="mfa@example.test", verified_at=timezone.now())
        reset_account_password(username=self.user.username, token=reset_tokens.make_token(self.user),
                               password="a different synthetic password 82!")
        self.assertTrue(SecondFactor.objects.get(user=self.user).enabled)
        payload["password"] = "a different synthetic password 82!"
        payload["code"] = ""
        self.assertEqual(self.post("login", payload).status_code, 400)

    def test_expired_setup_wrong_password_and_invalid_disable_fail(self):
        self.assertEqual(self.post("mfa", {"action": "begin", "password": "wrong"}).status_code, 400)
        self.assertFalse(SecondFactor.objects.exists())
        codes = self.enroll()
        self.assertEqual(self.post("mfa", {"action": "begin", "password": PASSWORD}).status_code, 400)
        self.assertEqual(self.post("mfa", {"action": "disable", "password": PASSWORD, "code": "000000"}).status_code, 400)
        self.assertEqual(self.post("mfa", {"action": "disable", "password": PASSWORD, "code": codes[0]}).status_code, 200)
        setup = self.post("mfa", {"action": "begin", "password": PASSWORD}).json()
        SecondFactor.objects.filter(user=self.user).update(created_at=timezone.now() - timedelta(minutes=11))
        self.assertEqual(self.post("mfa", {"action": "confirm", "password": PASSWORD,
                                          "code": mfa.hotp(setup["secret"], self.counter)}).status_code, 400)

    def test_csrf_authentication_ownership_and_failed_attempt_budget(self):
        self.assertEqual(self.client.post("/api/auth/mfa/", {}, content_type="application/json").status_code, 403)
        with override_settings(AUTH_REQUEST_LIMITS={"mfa-manage": (2, 3600)}):
            for _ in range(2):
                self.assertEqual(self.post("mfa", {"action": "begin", "password": "wrong"}).status_code, 400)
            self.assertEqual(self.post("mfa", {"action": "begin", "password": PASSWORD}).status_code, 429)
        self.client.logout()
        self.assertEqual(self.client.get("/api/auth/mfa/").status_code, 403)

    def test_fallback_key_can_decrypt_seed_after_controlled_rotation(self):
        codes = self.enroll()
        factor = SecondFactor.objects.get(user=self.user)
        from django.conf import settings
        old = settings.SECRET_KEY
        with override_settings(SECRET_KEY="new synthetic django key", SECRET_KEY_FALLBACKS=[old]):
            self.assertTrue(mfa.consume(factor, codes[0]))
            self.assertEqual(mfa.cipher().decrypt(factor.encrypted_secret.encode()).decode(), self.secret)

    def test_admin_renders_code_field_and_cannot_bypass_factor(self):
        self.user.is_staff = True
        self.user.save()
        codes = self.enroll()
        self.client.logout()
        response = self.client.get("/admin/login/")
        self.assertContains(response, 'name="code"')
        payload = {"username": self.user.username, "password": PASSWORD}
        response = self.client.post("/admin/login/", payload, HTTP_X_CSRFTOKEN=self.csrf())
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.client.get("/api/auth/session/").json()["user"])
        response = self.client.post("/admin/login/", {**payload, "code": codes[0]}, HTTP_X_CSRFTOKEN=self.csrf())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(self.client.get("/api/auth/sessions/").json()["sessions"]), 1)

    def test_enabling_revokes_other_sessions_and_rejects_overwriting_enabled_seed(self):
        other = Client()
        other.force_login(self.user)
        self.assertIsNotNone(other.get("/api/auth/session/").json()["user"])
        self.enroll()
        self.assertIsNone(other.get("/api/auth/session/").json()["user"])
        encrypted = SecondFactor.objects.get(user=self.user).encrypted_secret
        self.assertEqual(self.post("mfa", {"action": "begin", "password": PASSWORD}).status_code, 400)
        self.assertEqual(SecondFactor.objects.get(user=self.user).encrypted_secret, encrypted)


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False,
                   PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class SecondFactorConcurrencyTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_two_connections_can_consume_a_recovery_code_only_once(self):
        user = get_user_model().objects.create_user(username="mfa-race", password=PASSWORD)
        setup = mfa.begin(user)
        factor = SecondFactor.objects.get(user=user)
        counter = int(timezone.now().timestamp()) // 30
        code = mfa.enable(factor, mfa.hotp(setup["secret"], counter))[0]
        barrier = Barrier(2)

        def attempt():
            try:
                client = Client(enforce_csrf_checks=True)
                token = client.get("/api/auth/session/").json()["csrfToken"]
                barrier.wait(timeout=10)
                return client.post("/api/auth/login/", {"username": user.username, "password": PASSWORD, "code": code},
                                   content_type="application/json", HTTP_X_CSRFTOKEN=token).status_code
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = list(executor.map(lambda _: attempt(), range(2)))
        self.assertEqual(sorted(statuses), [200, 400])
        self.assertEqual(len(SecondFactor.objects.get(user=user).recovery_hashes), 9)
