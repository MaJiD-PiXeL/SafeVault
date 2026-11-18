"""Package a minimal Chrome/Edge MV3 extension bound to one vault origin."""
import argparse
import json
from pathlib import Path
import shutil
import re
from ipaddress import IPv4Address
from urllib.parse import urlsplit
from zipfile import ZipFile, ZIP_DEFLATED


def canonical_origin(origin):
    parsed = urlsplit(origin)
    if (parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or (parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost"})):
        raise ValueError("Use an HTTPS vault origin, or HTTP loopback for local testing.")
    host = parsed.hostname.lower()
    if any(ord(char) <= 32 for char in origin) or not re.fullmatch(r"[a-z0-9.-]+", host):
        raise ValueError("Use an ASCII DNS hostname or IPv4 address; enter international domains as Punycode.")
    if re.fullmatch(r"[0-9.]+", host):
        host = str(IPv4Address(host))
    elif len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.rstrip('.').split('.')):
        raise ValueError("Invalid vault hostname.")
    port = parsed.port
    suffix = f":{port}" if port is not None and port != (443 if parsed.scheme == "https" else 80) else ""
    return f"{parsed.scheme}://{host}{suffix}"


def build(origin, destination=None):
    origin = canonical_origin(origin)
    parsed = urlsplit(origin)
    root = Path(__file__).resolve().parent
    output = Path(destination) if destination else root / "dist" / "SafeVault-Extension"
    output.mkdir(parents=True, exist_ok=True)
    for filename in ("popup.html", "popup.js", "worker.js", "fill.js", "policy.js", "routing.js"):
        shutil.copyfile(root / filename, output / filename)
    (output / "config.js").write_text("export const vaultOrigin = " + json.dumps(origin) + ";\n", encoding="utf-8")
    manifest = {
        "manifest_version": 3, "name": "NEXORA SafeVault", "version": "0.1.0",
        "description": "Fill a login after choosing a matching entry in your unlocked SafeVault.",
        "permissions": ["activeTab", "scripting", "storage"],
        "action": {"default_popup": "popup.html"},
        "background": {"service_worker": "worker.js", "type": "module"},
        "externally_connectable": {"matches": [f"{parsed.scheme}://{parsed.hostname}/*"], "ids": []},
        "content_security_policy": {"extension_pages": "script-src 'self'; object-src 'none'"},
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    archive = output.parent / "SafeVault-Extension.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as bundle:
        for filename in sorted(output.iterdir()):
            if filename.is_file():
                bundle.write(filename, filename.name)
    return archive


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", default="http://127.0.0.1:18010")
    args = parser.parse_args()
    print(build(args.origin))
