from django.core.checks import Tags, run_checks
from django.test import RequestFactory, SimpleTestCase, override_settings

from .checks import production_configuration, secure_origin
from .security import client_ip


class ProxyClientIPTests(SimpleTestCase):
    def test_client_ip_header_only_applies_to_the_bundled_unix_proxy(self):
        factory = RequestFactory()
        request = factory.get("/", REMOTE_ADDR="", HTTP_X_SAFEVAULT_CLIENT_IP="192.0.2.2")
        self.assertEqual(client_ip(request), "0.0.0.0")
        with override_settings(TRUST_UNIX_PROXY=True):
            self.assertEqual(client_ip(request), "192.0.2.2")
            request.META["REMOTE_ADDR"] = "192.0.2.3"
            self.assertEqual(client_ip(request), "192.0.2.3")
            request.META["REMOTE_ADDR"] = ""
            request.META["HTTP_X_SAFEVAULT_CLIENT_IP"] = "192.0.2.2, 192.0.2.4"
            self.assertEqual(client_ip(request), "0.0.0.0")


@override_settings(
    PRODUCTION=True, DEBUG=False, ALLOWED_HOSTS=["vault.example.com"],
    ACCOUNT_LINK_ORIGIN="https://vault.example.com",
    DEFAULT_FROM_EMAIL="SafeVault <no-reply@vault.example.com>",
    CORS_ALLOWED_ORIGINS=[], CSRF_TRUSTED_ORIGINS=[],
    SESSION_COOKIE_SECURE=True, CSRF_COOKIE_SECURE=True, SECURE_SSL_REDIRECT=True,
    MAILERS={"default": {"BACKEND": "django.core.mail.backends.smtp.EmailBackend", "OPTIONS": {"host": "smtp.example.com", "use_tls": True}}},
)
class DeploymentCheckTests(SimpleTestCase):
    def test_same_origin_production_configuration(self):
        self.assertEqual(production_configuration(None), [])

    def test_checks_are_registered_for_deployment_only(self):
        with override_settings(ALLOWED_HOSTS=["*"]):
            ordinary = run_checks(tags=[Tags.security])
            deployment = run_checks(tags=[Tags.security], include_deployment_checks=True)
        self.assertNotIn("safevault.E002", [message.id for message in ordinary])
        self.assertIn("safevault.E002", [message.id for message in deployment])

    def test_invalid_settings_fail_without_disclosing_values(self):
        for changes, code in [
            ({"PRODUCTION": False}, "safevault.E001"),
            ({"ALLOWED_HOSTS": []}, "safevault.E002"),
            ({"ALLOWED_HOSTS": [".example.com"]}, "safevault.E002"),
            ({"ALLOWED_HOSTS": ["localhost"]}, "safevault.E002"),
            ({"CORS_ALLOWED_ORIGINS": ["http://example.com"]}, "safevault.E003"),
            ({"CSRF_TRUSTED_ORIGINS": ["https://private-user:private-secret@example.com"]}, "safevault.E004"),
            ({"SESSION_COOKIE_SECURE": False}, "safevault.E005"),
            ({"CSRF_COOKIE_SECURE": False}, "safevault.E005"),
            ({"SECURE_SSL_REDIRECT": False}, "safevault.E005"),
            ({"DEBUG": True}, "safevault.E005"),
            ({"ACCOUNT_LINK_ORIGIN": "http://vault.example.com"}, "safevault.E007"),
            ({"DEFAULT_FROM_EMAIL": "SafeVault <no-reply@localhost>"}, "safevault.E008"),
            ({"MAILERS": {"default": {"BACKEND": "django.core.mail.backends.smtp.EmailBackend", "OPTIONS": {"host": " "}}}}, "safevault.E006"),
        ]:
            with self.subTest(code=code, changes=changes), override_settings(**changes):
                messages = production_configuration(None)
                self.assertIn(code, [message.id for message in messages])
                self.assertNotIn("private-secret", str(messages))

    def test_explicit_https_origin_validation(self):
        for origin in ["https://vault.example.com", "https://vault.example.com:8443"]:
            self.assertTrue(secure_origin(origin))
        for origin in ["*", "https://*.example.com", "http://example.com", "https://localhost", "https://[::1]", "https://example.com/", "https://example.com/path", "https://example.com?x=1", "https://example.com#fragment", "https://example.com:bad", "https://[bad", "https://example.com:0", "https://example.com:65536"]:
            with self.subTest(origin=origin):
                self.assertFalse(secure_origin(origin))
