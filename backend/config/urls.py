from django.contrib import admin
from django.http import JsonResponse
from django.urls import path, include
from django.views.decorators.http import require_GET


@require_GET
def home(request):
    return JsonResponse({
        "app": "VELNAR SAFEVAULT",
        "status": "online",
        "version": "0.1.0",
        "api": "/api/",
        "health": "/api/health/",
    })


urlpatterns = [
    path("", home, name="root"),
    path("admin/", admin.site.urls),
    path("api/auth/", include("accounts.urls")),
    path("api/", include("vault.urls")),
]
