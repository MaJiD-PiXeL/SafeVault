from django.conf import settings
from django.contrib.sessions.models import Session
from django.core.management.base import BaseCommand
from django.utils import timezone

from axes.models import AccessAttempt
from accounts.models import AuthRequestWindow


class Command(BaseCommand):
    help = "Remove only expired sessions and authentication counters. Vault data is untouched."

    def handle(self, *args, **options):
        now = timezone.now()
        windows, _ = AuthRequestWindow.objects.filter(expires_at__lte=now).delete()
        sessions, _ = Session.objects.filter(expire_date__lte=now).delete()
        attempts, _ = AccessAttempt.objects.filter(attempt_time__lt=now - settings.AXES_COOLOFF_TIME).delete()
        self.stdout.write(f"Expired auth state removed: {windows} counters, {sessions} session rows, {attempts} attempt rows.")
