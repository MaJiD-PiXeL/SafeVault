import importlib.util
import os
from pathlib import Path
import stat
import tempfile
from unittest.mock import patch

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


class SecretStageTests(SimpleTestCase):
    def test_atomic_replacement_preserves_private_access_and_ignores_old_stage(self):
        rotation = module("review_secret_rotation", "deploy/rotate-local-secrets.py")
        with tempfile.TemporaryDirectory() as directory:
            environment = Path(directory) / ".env"
            environment.write_text("PUBLIC old value", encoding="utf-8")
            if os.name != "nt":
                environment.chmod(0o600)
            stale = Path(directory) / ".env.rotation-stage"
            stale.write_text("Do not follow or overwrite this path", encoding="utf-8")
            with patch.object(rotation, "ENV", environment):
                rotation.write_env("PUBLIC replacement value")
            self.assertEqual(environment.read_text(), "PUBLIC replacement value")
            self.assertEqual(stale.read_text(), "Do not follow or overwrite this path")
            self.assertFalse(list(Path(directory).glob(".env.rotation-stage-*")))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(environment.stat().st_mode), 0o600)

    def test_failed_replace_keeps_original_and_removes_only_the_unique_stage(self):
        rotation = module("review_secret_rotation_failure", "deploy/rotate-local-secrets.py")
        with tempfile.TemporaryDirectory() as directory:
            environment = Path(directory) / ".env"
            environment.write_text("PUBLIC original", encoding="utf-8")
            with patch.object(rotation, "ENV", environment), patch.object(rotation.os, "replace", side_effect=OSError("synthetic")):
                with self.assertRaises(OSError):
                    rotation.write_env("PUBLIC replacement")
            self.assertEqual(environment.read_text(), "PUBLIC original")
            self.assertFalse(list(Path(directory).glob(".env.rotation-stage-*")))


class ExtensionOriginTests(SimpleTestCase):
    def test_packaged_origin_is_canonical_and_routing_worker_is_included(self):
        builder = module("review_extension_build", "native/extension/build.py")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "extension"
            builder.build("https://VAULT.EXAMPLE.COM:443/", output)
            self.assertIn('"https://vault.example.com"', (output / "config.js").read_text())
            self.assertTrue((output / "routing.js").is_file())
            self.assertIn('https://vault.example.com/*', (output / "manifest.json").read_text())
        self.assertEqual(builder.canonical_origin("http://LOCALHOST:80/"), "http://localhost")
        self.assertEqual(builder.canonical_origin("https://VAULT.EXAMPLE.COM:8443/"), "https://vault.example.com:8443")
        for bad in ("https://user:password@vault.test", "https://vault.test/path", "https://vault.test:99999", "https://127.1", "https://vault.test\n"):
            with self.subTest(origin=bad), self.assertRaises(ValueError):
                builder.canonical_origin(bad)
