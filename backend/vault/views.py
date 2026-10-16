from django.http import JsonResponse
from django.views.decorators.http import require_GET


@require_GET
def home(request):
    return JsonResponse({
        "app": "VELNAR SAFEVAULT",
        "status": "online",
        "version": "0.1.0",
    })


@require_GET
def health_check(request):
    return JsonResponse({
        "status": "healthy",
    })