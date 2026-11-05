from django.db import DatabaseError, connection
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET


@require_GET
def home(request):
    return JsonResponse({
        "app": "NEXORA SafeVault",
        "status": "online",
        "version": "0.1.0",
    })


@require_GET
def health_check(request):
    return JsonResponse({
        "status": "healthy",
    })


@require_GET
@never_cache
def readiness_check(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
    except DatabaseError:
        return JsonResponse({"status": "unavailable"}, status=503)
    return JsonResponse({"status": "ready"})
