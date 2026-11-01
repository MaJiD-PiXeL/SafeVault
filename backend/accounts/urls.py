from django.urls import path

from . import views

app_name = "accounts"
urlpatterns = [
    path("session/", views.SessionView.as_view(), name="session"),
    path("register/", views.RegisterView.as_view(), name="register"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("sessions/", views.SessionsView.as_view(), name="sessions"),
    path("sessions/<uuid:session_id>/", views.RevokeSessionView.as_view(), name="revoke-session"),
]
