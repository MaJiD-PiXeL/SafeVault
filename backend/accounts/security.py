from datetime import datetime, timezone as datetime_timezone
from ipaddress import ip_address

from django.conf import settings
from django.db.models import F
from django.http import JsonResponse
from django.utils import timezone
from django.utils.crypto import salted_hmac
from rest_framework.exceptions import Throttled

from .models import AuthRequestWindow


def client_ip(request):
    # Forwarded headers are untrusted. A production proxy must set REMOTE_ADDR
    # from its own verified peer chain before the request reaches Django.
    try:
        return ip_address(request.META.get("REMOTE_ADDR", "")).compressed
    except ValueError:
        return "0.0.0.0"


def limit_requests(request, scope):
    limit, seconds = settings.AUTH_REQUEST_LIMITS[scope]
    now = int(timezone.now().timestamp())
    window = now // seconds
    key = salted_hmac("velnar.auth.request.v1", f"{scope}:{client_ip(request)}:{window}", algorithm="sha256").hexdigest()
    expires_at = datetime.fromtimestamp((window + 1) * seconds, tz=datetime_timezone.utc)
    AuthRequestWindow.objects.get_or_create(key=key, defaults={"expires_at": expires_at})
    # A single conditional UPDATE is atomic even across application workers.
    allowed = AuthRequestWindow.objects.filter(key=key, attempts__lt=limit).update(attempts=F("attempts") + 1)
    if not allowed:
        raise Throttled(wait=(window + 1) * seconds - now)


def csrf_failure(request, reason=""):
    response = JsonResponse({"detail": "Security token expired. Refresh and try again.", "code": "csrf_failed"}, status=403)
    response["Cache-Control"] = "no-store"
    return response


def lockout_response(request, response=None, credentials=None, **kwargs):
    response = JsonResponse({"detail": "Too many sign-in attempts. Try again later."}, status=429)
    response["Cache-Control"] = "no-store"
    response["Retry-After"] = str(int(settings.AXES_COOLOFF_TIME.total_seconds()))
    return response
