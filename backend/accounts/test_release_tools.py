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


def protect_windows_acl(path):
    """Make the synthetic source differ from its parent's inherited protection."""
    import ctypes
    from ctypes import wintypes
    library = ctypes.WinDLL("advapi32")
    pointer = ctypes.c_void_p
    library.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                             ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.POINTER(pointer),
                                             ctypes.POINTER(pointer), ctypes.POINTER(pointer)]
    library.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
                                             pointer, pointer, pointer, pointer]
    dacl, descriptor = pointer(), pointer()
    if library.GetNamedSecurityInfoW(str(path), 1, 4, None, None, ctypes.byref(dacl), None, ctypes.byref(descriptor)):
        raise OSError("Could not read the synthetic file ACL")
    try:
        if library.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, dacl, None):
            raise OSError("Could not protect the synthetic file ACL")
    finally:
        kernel = ctypes.WinDLL("kernel32")
        kernel.LocalFree.argtypes = [pointer]
        kernel.LocalFree(descriptor)


class SecretStageTests(SimpleTestCase):
    def test_atomic_replacement_preserves_private_access_and_ignores_old_stage(self):
        rotation = module("review_secret_rotation", "deploy/rotate-local-secrets.py")
        with tempfile.TemporaryDirectory() as directory:
            environment = Path(directory) / ".env"
            environment.write_text("PUBLIC old value", encoding="utf-8")
            if os.name != "nt":
                environment.chmod(0o600)
            else:
                protect_windows_acl(environment)
            original_access = rotation.windows_access(environment) if os.name == "nt" else None
            if os.name == "nt":
                if not original_access[0]:
                    self.skipTest("Filesystem sandbox virtualizes DACL protection; run the native Windows suite.")
            stale = Path(directory) / ".env.rotation-stage"
            stale.write_text("Do not follow or overwrite this path", encoding="utf-8")
            with patch.object(rotation, "ENV", environment):
                rotation.write_env("PUBLIC replacement value")
            self.assertEqual(environment.read_text(), "PUBLIC replacement value")
            self.assertEqual(stale.read_text(), "Do not follow or overwrite this path")
            self.assertFalse(list(Path(directory).glob(".env.rotation-stage-*")))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(environment.stat().st_mode), 0o600)
            else:
                self.assertEqual(rotation.windows_access(environment), original_access)

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
