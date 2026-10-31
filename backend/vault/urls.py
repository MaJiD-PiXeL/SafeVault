from django.urls import path
from . import views

app_name = "vault"

urlpatterns = [
    path("", views.home, name="home"),
    path("health/", views.health_check, name="health"),
]
