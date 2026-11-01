import uuid

from django.conf import settings
from django.contrib.sessions.models import Session
from django.db import models


class AccountSession(models.Model):
    """Public session identifiers are independent of bearer session cookies."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="account_sessions")
    session = models.OneToOneField(Session, on_delete=models.CASCADE, related_name="account_session")
    created_at = models.DateTimeField(auto_now_add=True)


class AuthRequestWindow(models.Model):
    """Short-lived HMAC identifiers for an atomic, cross-worker request budget."""
    key = models.CharField(primary_key=True, max_length=64)
    attempts = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField(db_index=True)
