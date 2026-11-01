from django.contrib.auth import get_user_model, login
from django.contrib.sessions.models import Session
from django.db import transaction
from django.utils import timezone
from django.views.decorators.debug import sensitive_variables

from vault.models import SecuritySettings
from .models import AccountSession


@sensitive_variables()
@transaction.atomic
def register_account(*, request, username, password):
    user = get_user_model().objects.create_user(username=username, password=password)
    SecuritySettings.objects.create(user=user)
    start_session(request, user)
    return user


@transaction.atomic
def start_session(request, user):
    # Serialize sign-ins for this user before imposing the active-session cap.
    get_user_model().objects.select_for_update().get(pk=user.pk)
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    request.session.save()
    AccountSession.objects.get_or_create(user=user, session_id=request.session.session_key)
    excess = list(AccountSession.objects.filter(user=user, session__expire_date__gt=timezone.now())
                  .exclude(session_id=request.session.session_key)
                  .order_by("-created_at", "id").values_list("session_id", flat=True)[9:])
    Session.objects.filter(session_key__in=excess).delete()


def active_sessions(user):
    return AccountSession.objects.filter(user=user, session__expire_date__gt=timezone.now()).select_related("session").order_by("-created_at")


@transaction.atomic
def revoke_session(*, user, session_id):
    record = active_sessions(user).select_for_update().get(pk=session_id)
    record.session.delete()
