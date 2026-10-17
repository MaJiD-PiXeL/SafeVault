from django.contrib import admin
from django.http import JsonResponse
from django.urls import path, include


def home(request):
    return JsonResponse({
        "app": "VELNAR SAFEVAULT",
        "status": "online",
        "version": "0.1.0",
        "api": "/api/",
        "health": "/api/health/",
    })


urlpatterns = [
    path("", home, name="home"),
    path("admin/", admin.site.urls),
    path("api/", include("vault.urls")),
]