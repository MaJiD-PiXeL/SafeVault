import sys
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory, TestCase, override_settings
from django.utils import timezone
from django.views.debug import ExceptionReporter

from . import mfa
from .admin import SecondFactorAdminForm
from .models import PasswordResetRequest, RecoveryEmail, SecondFactor
from .recovery import reset_tokens, verification_tokens


@override_settings(ALLOWED_HOSTS=["testserver"], SECURE_SSL_REDIRECT=False, DEBUG=False,
                   PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
                   ACCOUNT_LINK_ORIGIN="https://vault.example.test",
                   MAILERS={"default": {"BACKEND": "django.core.mail.backends.locmem.EmailBackend"}})
class ReviewRegressionTests(TestCase):
    password = "PUBLIC synthetic account phrase 29!"

    def setUp(self):
        self.user = get_user_model().objects.create_user(username="review-user", password=self.password, is_staff=True, is_superuser=True)
        self.client = Client(enforce_csrf_checks=True)

    def write(self, route, data, method="post"):
        token = self.client.get("/api/auth/session/").json()["csrfToken"]
        return getattr(self.client, method)("/api/auth/" + route + "/", data, content_type="application/json", HTTP_X_CSRFTOKEN=token)

    def factor(self):
        setup = mfa.begin(self.user)
        factor = SecondFactor.objects.get(user=self.user)
        codes = mfa.enable(factor, mfa.hotp(setup["secret"], int(timezone.now().timestamp()) // 30))
        return factor, codes

    def test_admin_rejects_password_only_api_session_until_mfa_is_proved(self):
        self.assertEqual(self.write("login", {"username": self.user.username, "password": self.password}).status_code, 200)
        for route in ("/admin/", "/admin/auth/user/"):
            self.assertEqual(self.client.get(route).status_code, 302)
        factor, codes = self.factor()
        # Having an enrolled factor alone does not upgrade a password-only session.
        self.assertEqual(self.client.get("/admin/").status_code, 302)
        self.client.logout()
        self.assertEqual(self.write("login", {"username": self.user.username, "password": self.password, "code": codes[0]}).status_code, 200)
        self.assertEqual(self.client.get("/admin/").status_code, 200)
        self.assertEqual(self.write("mfa", {"action": "disable", "password": self.password, "code": codes[1]}).status_code, 200)
        self.assertEqual(self.client.get("/admin/").status_code, 302)
        # A later enrollment cannot reuse the earlier session proof.
        self.factor()
        self.assertEqual(self.client.get("/admin/").status_code, 302)

    def test_admin_exception_html_redacts_both_credentials(self):
        password = self.password
        recovery = "PUBLIC-" + "synthetic-recovery-code-83"
        request = RequestFactory().post("/admin/login/", {"username": self.user.username, "password": password, "code": recovery})
        request.sensitive_post_parameters = "__ALL__"
        try:
            with patch("accounts.admin.limit_requests", side_effect=RuntimeError("synthetic error")):
                SecondFactorAdminForm(request=request, data=request.POST).is_valid()
        except RuntimeError:
            kind, value, trace = sys.exc_info()
            # Exclude this test frame, which deliberately holds the public fixtures.
            reporter = ExceptionReporter(request, kind, value, trace.tb_next)
            for body in (reporter.get_traceback_html(), reporter.get_traceback_text()):
                self.assertNotIn(password, body)
                self.assertNotIn(recovery, body)
        else:
            self.fail("Synthetic failure did not exercise the error reporter")

    def test_recovery_codes_can_be_replaced_without_disabling_mfa(self):
        factor, codes = self.factor()
        self.client.force_login(self.user)
        self.assertEqual(self.write("mfa", {"action": "regenerate", "password": self.password, "code": "wrong"}).status_code, 400)
        response = self.write("mfa", {"action": "regenerate", "password": self.password, "code": codes[0]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["recoveryCodes"]), 10)
        factor.refresh_from_db()
        self.assertTrue(factor.enabled)
        self.assertFalse(mfa.consume(factor, codes[1]))
        self.assertTrue(mfa.consume(factor, response.json()["recoveryCodes"][0]))

    def test_change_and_remove_recovery_email_require_mfa_and_revoke_old_links(self):
        factor, codes = self.factor()
        self.client.force_login(self.user)
        address = RecoveryEmail.objects.create(user=self.user, email="old@example.test", verified_at=timezone.now())
        old_reset = reset_tokens.make_token(self.user)
        PasswordResetRequest.objects.create(username=self.user.username)
        data = {"email": "new@example.test", "password": self.password}
        self.assertEqual(self.write("recovery/email", data).status_code, 400)
        address.refresh_from_db()
        self.assertEqual(address.email, "old@example.test")
        self.assertEqual(self.write("recovery/email", {**data, "code": codes[0]}).status_code, 204)
        address.refresh_from_db()
        self.assertEqual(address.email, "new@example.test")
        self.assertIsNone(address.verified_at)
        self.assertFalse(PasswordResetRequest.objects.exists())
        self.assertEqual(self.write("recovery/reset", {"username": self.user.username, "token": old_reset, "password": "PUBLIC replacement account phrase 71!"}).status_code, 400)
        self.user.recovery_email = address
        old_verification = verification_tokens.make_token(self.user)
        self.assertEqual(self.write("recovery/email", {"password": self.password}, "delete").status_code, 400)
        self.assertEqual(self.write("recovery/email", {"password": self.password, "code": codes[1]}, "delete").status_code, 204)
        self.assertFalse(RecoveryEmail.objects.exists())
        # Even re-adding the identical pending address must not revive its old link.
        self.assertEqual(self.write("recovery/email", {**data, "code": codes[2]}).status_code, 204)
        self.assertEqual(self.write("recovery/verify", {"username": self.user.username, "token": old_verification}).status_code, 400)

    def test_remove_recovery_email_enforces_csrf(self):
        self.client.force_login(self.user)
        RecoveryEmail.objects.create(user=self.user, email="old@example.test", verified_at=timezone.now())
        response = self.client.delete("/api/auth/recovery/email/", {"password": self.password}, content_type="application/json")
        self.assertEqual(response.status_code, 403)
        self.assertTrue(RecoveryEmail.objects.exists())
