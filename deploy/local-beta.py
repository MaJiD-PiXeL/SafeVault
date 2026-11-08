"""Serve the built SafeVault on loopback with a disposable database and file mailbox."""
import argparse
import logging
import mimetypes
import os
from pathlib import Path
import secrets
from shutil import copytree
from socketserver import ThreadingMixIn
import sys
import tempfile
from threading import Event, Thread
from wsgiref.simple_server import WSGIServer, make_server
from wsgiref.util import FileWrapper


ROOT = Path(__file__).resolve().parents[1]
DIST = (ROOT / "frontend" / "dist").resolve()
CSP = ("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; "
       "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


class LocalServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def frontend(django_app, host, dist):
    def application(env, start):
        path = env.get("PATH_INFO", "/")
        if env.get("HTTP_HOST") != host:
            start("400 Bad Request", [("Content-Length", "0")])
            return []
        if path.startswith("/api/"):
            return django_app(env, start)
        method = env["REQUEST_METHOD"]
        if method not in ("GET", "HEAD"):
            start("405 Method Not Allowed", [("Allow", "GET, HEAD"), ("Content-Length", "0")])
            return []
        name = "index.html" if path == "/" else path.lstrip("/")
        file = (dist / name).resolve()
        if not file.is_relative_to(dist) or not file.is_file() or file.suffix == ".map":
            start("404 Not Found", [("Content-Length", "0")])
            return []
        mime = "text/javascript" if file.suffix == ".js" else mimetypes.guess_type(file.name)[0] or "application/octet-stream"
        start("200 OK", [("Content-Type", mime), ("Content-Length", str(file.stat().st_size)),
                         ("Cache-Control", "no-cache"), ("Content-Security-Policy", CSP),
                         ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer")])
        return [] if method == "HEAD" else FileWrapper(file.open("rb"))
    return application


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18010)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Choose a port between 1024 and 65535.")
    if not (DIST / "index.html").is_file() or not (DIST / "offline-shell.js").is_file():
        parser.error("Run npm run build in frontend first.")

    host = f"127.0.0.1:{args.port}"
    origin = f"http://{host}"
    state = Path(tempfile.mkdtemp(prefix="safevault-beta-")).resolve()
    site = state / "site"
    copytree(DIST, site)
    mailbox = state / "mail"
    mailbox.mkdir()
    sys.path.insert(0, str(ROOT / "backend"))
    # Use only the synthetic beta environment. Never load the project's .env file.
    os.environ.pop("DJANGO_SECRET_KEY_FILE", None)
    os.environ.update(DJANGO_SETTINGS_MODULE="config.settings", DJANGO_SECRET_KEY=secrets.token_urlsafe(48),
                      DJANGO_ENV="development", DJANGO_DEBUG="False", PYTHON_DOTENV_DISABLED="1")

    from django.conf import settings
    from django.core.management import call_command
    from django.core.wsgi import get_wsgi_application
    from django.db import OperationalError, close_old_connections

    settings.DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": state / "beta.sqlite3",
                                      "OPTIONS": {"transaction_mode": "IMMEDIATE"}}}
    settings.ALLOWED_HOSTS = ["127.0.0.1"]
    settings.CSRF_TRUSTED_ORIGINS = []
    settings.CORS_ALLOWED_ORIGINS = []
    settings.SESSION_COOKIE_NAME = f"safevault_beta_session_{args.port}"
    settings.CSRF_COOKIE_NAME = f"safevault_beta_csrf_{args.port}"
    settings.ACCOUNT_LINK_ORIGIN = origin
    settings.DEFAULT_FROM_EMAIL = "SafeVault Local Beta <no-reply@safevault.test>"
    settings.MAILERS = {"default": {"BACKEND": "django.core.mail.backends.filebased.EmailBackend",
                                    "OPTIONS": {"file_path": str(mailbox)}}}

    application = frontend(get_wsgi_application(), host, site)
    from accounts.recovery import dispatch_reset_requests

    errors = logging.StreamHandler()
    errors.setLevel(logging.ERROR)
    logging.getLogger("django.request").addHandler(errors)
    stop = Event()

    def send_mail():
        while not stop.wait(2):
            close_old_connections()
            try:
                _, failed = dispatch_reset_requests()
                if failed:
                    print("The beta could not write a recovery email to its local mailbox.", file=sys.stderr, flush=True)
            except OperationalError:
                # A concurrent SQLite request may hold the write lock; retry next poll.
                continue
        close_old_connections()

    with make_server("127.0.0.1", args.port, application, server_class=LocalServer) as server:
        call_command("migrate", interactive=False, verbosity=0)
        print(f"Local SafeVault beta: {origin}/\nLocal mailbox: {mailbox}", flush=True)
        Thread(target=send_mail, daemon=True).start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()


if __name__ == "__main__":
    main()
