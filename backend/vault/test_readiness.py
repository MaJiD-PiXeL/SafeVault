from unittest.mock import patch

from django.db import OperationalError
from django.test import TestCase


class ReadinessTests(TestCase):
    def test_readiness_checks_database_and_disables_cache(self):
        response = self.client.get("/api/ready/")
        self.assertEqual(response.json(), {"status": "ready"})
        self.assertIn("no-store", response["Cache-Control"])


    def test_liveness_stays_healthy_when_readiness_fails(self):
        with patch("vault.views.connection.cursor", side_effect=OperationalError("private details")):
            self.assertEqual(self.client.get("/api/health/").json(), {"status": "healthy"})
            response = self.client.get("/api/ready/")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"status": "unavailable"})
        self.assertIn("no-store", response["Cache-Control"])
