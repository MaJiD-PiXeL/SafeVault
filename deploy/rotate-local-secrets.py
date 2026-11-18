"""Rotate this checkout's loopback PostgreSQL password and Django key together.

Never prints credentials. An ACL-protected recovery journal handles interruption
between the database transaction and the atomic environment-file replacement.
"""
import argparse
import base64
import csv
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import stat
import tempfile

from cryptography.fernet import Fernet
from dotenv import dotenv_values
import psycopg
from psycopg import sql

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / "backend" / ".env"
DIRECTORY = ROOT / "deploy" / "secrets"
JOURNAL = DIRECTORY / "local-rotation.json"


def protect_directory():
    DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "nt":
        result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], check=True, capture_output=True, text=True)
        sid = next(csv.reader(io.StringIO(result.stdout)))[1]
        subprocess.run(["icacls", str(DIRECTORY), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                       check=True, capture_output=True)
    else:
        DIRECTORY.chmod(0o700)


def values(text):
    return dotenv_values(stream=io.StringIO(text))


def connect(config):
    if config.get("DB_HOST") not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("This tool only rotates the local loopback database.")
    return psycopg.connect(dbname=config["DB_NAME"], user=config["DB_USER"], password=config["DB_PASSWORD"],
                          host=config["DB_HOST"], port=config.get("DB_PORT", "5432"), connect_timeout=5)


def replacement(text, name, value):
    pattern = rf"(?m)^{name}=.*$"
    if len(re.findall(pattern, text)) != 1:
        raise ValueError("Expected one explicit environment setting for " + name)
    return re.sub(pattern, name + "=" + value, text)


def write_env(text):
    if ENV.is_symlink() or not ENV.is_file():
        raise ValueError("The environment must be an existing regular file.")
    descriptor, filename = tempfile.mkstemp(prefix=".env.rotation-stage-", dir=ENV.parent)
    staged = Path(filename)
    try:
        # Apply access controls before any credential bytes reach the stage.
        if os.name == "nt":
            subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
                            str(ROOT / "deploy" / "copy-file-acl.ps1"), "-Source", str(ENV),
                            "-Destination", str(staged)], check=True, capture_output=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            os.fchmod(descriptor, stat.S_IMODE(ENV.stat().st_mode) & 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(text.encode("utf-8")); output.flush(); os.fsync(output.fileno())
        os.replace(staged, ENV)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if staged.exists():
            staged.unlink()


def seed_cipher(key):
    return Fernet(base64.urlsafe_b64encode(hmac.digest(key.encode(), b"safevault.totp.encryption.v1", "sha256")))


def recover():
    journal = json.loads(JOURNAL.read_text(encoding="utf-8"))
    for side in ("replacement", "previous"):
        try:
            with connect(values(journal[side])) as connection:
                connection.execute("SELECT 1")
        except psycopg.OperationalError:
            continue
        write_env(journal[side])
        JOURNAL.unlink()
        print("Recovered a consistent local configuration. Restart Django and its mail worker.")
        return
    raise RuntimeError("Database unavailable. Keep the protected journal and retry --recover when it is reachable.")


def rotate():
    if JOURNAL.exists():
        raise RuntimeError("An unfinished rotation exists. Run this tool with --recover first.")
    previous = ENV.read_bytes().decode("utf-8")
    config = values(previous)
    if any(config.get(name + "_FILE") or os.getenv(name) or os.getenv(name + "_FILE")
           for name in ("DB_PASSWORD", "DJANGO_SECRET_KEY")):
        raise ValueError("Remove environment overrides before rotating this checkout's .env configuration.")
    new_key, new_password = secrets.token_urlsafe(64), secrets.token_urlsafe(48)
    updated = replacement(replacement(previous, "DJANGO_SECRET_KEY", new_key), "DB_PASSWORD", new_password)
    # Validate connection before creating a recovery journal.
    with connect(config) as connection:
        role = connection.execute("SELECT current_user").fetchone()[0]
        protect_directory()
        with JOURNAL.open("x", encoding="utf-8") as output:
            json.dump({"previous": previous, "replacement": updated}, output)
            output.flush(); os.fsync(output.fileno())
        connection.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(new_password)))
        if connection.execute("SELECT to_regclass('accounts_secondfactor')").fetchone()[0]:
            old_cipher, new_cipher = seed_cipher(config["DJANGO_SECRET_KEY"]), seed_cipher(new_key)
            for pk, encrypted in connection.execute("SELECT id, encrypted_secret FROM accounts_secondfactor FOR UPDATE").fetchall():
                refreshed = new_cipher.encrypt(old_cipher.decrypt(encrypted.encode())).decode()
                connection.execute("UPDATE accounts_secondfactor SET encrypted_secret=%s WHERE id=%s", (refreshed, pk))
        for table in ("django_session", "accounts_passwordresetrequest"):
            if connection.execute("SELECT to_regclass(%s)", (table,)).fetchone()[0]:
                connection.execute(sql.SQL("DELETE FROM {}").format(sql.Identifier(table)))
        write_env(updated)
    # The journal is retained if the commit outcome or reconnect is uncertain.
    with connect(values(updated)) as connection:
        connection.execute("SELECT 1")
    JOURNAL.unlink()
    print("Rotated local Django and PostgreSQL credentials; verified the new connection.")
    print("Invalidated account sessions and queued reset emails. Vault ciphertext and keys were preserved.")
    print("Restart Django and its mail worker. Old signed account links are invalid.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recover", action="store_true")
    args = parser.parse_args()
    try:
        recover() if args.recover else rotate()
    except Exception as error:
        # Connection errors can contain connection details; print only the type.
        print(f"Rotation did not finish ({type(error).__name__}).", file=sys.stderr)
        if isinstance(error, (ValueError, RuntimeError)):
            print(str(error), file=sys.stderr)
        if JOURNAL.exists():
            print("Protected recovery journal retained. Run --recover before retrying. Do not delete the journal.", file=sys.stderr)
        sys.exit(1)
