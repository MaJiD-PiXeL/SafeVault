from django.test import SimpleTestCase, override_settings
from django.urls import reverse


@override_settings(DEBUG=False, ALLOWED_HOSTS=["localhost", "127.0.0.1", "testserver"])
class PublicEndpointTests(SimpleTestCase):
    def test_endpoints_return_json_without_database_access(self):
        for name in ("root", "vault:home", "vault:health"):
            with self.subTest(name=name):
                response = self.client.get(reverse(name))
                self.assertEqual(response.status_code, 200)
                self.assertIn("status", response.json())

    def test_localhost_works_with_debug_disabled(self):
        response = self.client.get("/api/health/", HTTP_HOST="127.0.0.1:8000")
        self.assertEqual(response.json(), {"status": "healthy"})

    def test_endpoints_reject_mutations(self):
        for path in ("/", "/api/", "/api/health/"):
            with self.subTest(path=path):
                self.assertEqual(self.client.post(path).status_code, 405)

    def test_unknown_host_is_rejected(self):
        response = self.client.get("/api/health/", HTTP_HOST="untrusted.example")
        self.assertEqual(response.status_code, 400)

    def test_frontend_origin_receives_cors_headers(self):
        response = self.client.get("/api/health/", HTTP_ORIGIN="http://localhost:5173")
        self.assertEqual(response["Access-Control-Allow-Origin"], "http://localhost:5173")

    def test_untrusted_origin_receives_no_cors_permission(self):
        response = self.client.get("/api/health/", HTTP_ORIGIN="https://untrusted.example")
        self.assertNotIn("Access-Control-Allow-Origin", response)
