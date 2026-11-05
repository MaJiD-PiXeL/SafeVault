from django.urls import path

from . import recovery_views, views

app_name = "accounts"
urlpatterns = [
    path("session/", views.SessionView.as_view(), name="session"),
    path("register/", views.RegisterView.as_view(), name="register"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("sessions/", views.SessionsView.as_view(), name="sessions"),
    path("sessions/<uuid:session_id>/", views.RevokeSessionView.as_view(), name="revoke-session"),
    path("recovery/email/", recovery_views.RecoveryEmailView.as_view(), name="recovery-email"),
    path("recovery/verify/", recovery_views.VerifyRecoveryEmailView.as_view(), name="recovery-verify"),
    path("recovery/request/", recovery_views.RequestPasswordResetView.as_view(), name="recovery-request"),
    path("recovery/reset/", recovery_views.ResetAccountPasswordView.as_view(), name="recovery-reset"),
]
