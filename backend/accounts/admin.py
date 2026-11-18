from django import forms
from django.contrib import admin
from django.contrib.admin.forms import AdminAuthenticationForm
from django.contrib.auth import get_user_model
from django.db import transaction
from django.views.decorators.debug import sensitive_variables
from rest_framework.exceptions import Throttled

from .mfa import consume, mark_verified
from .models import SecondFactor
from .security import limit_requests


class SecondFactorAdminForm(AdminAuthenticationForm):
    code = forms.CharField(label="Authenticator or recovery code", required=False,
                           max_length=64, widget=forms.PasswordInput(attrs={"autocomplete": "one-time-code"}))

    @sensitive_variables()
    def clean(self):
        cleaned = super().clean()
        user = self.get_user()
        if user:
            # Apply before the atomic block so failed attempts keep their budget.
            try:
                limit_requests(self.request, "mfa-login-user", subject=str(user.pk))
            except Throttled:
                raise forms.ValidationError("Too many verification attempts. Try again later.") from None
            with transaction.atomic():
                locked = get_user_model().objects.select_for_update().get(pk=user.pk)
                factor = SecondFactor.objects.filter(user=locked, enabled=True).first()
                if not locked.is_active or locked.password != user.password or not factor or not consume(factor, cleaned.get("code", "")):
                    raise forms.ValidationError("Set up two-step verification in the vault account settings, then enter a fresh code.")
                mark_verified(self.request, factor)
        return cleaned


admin.site.login_form = SecondFactorAdminForm
admin.site.login_template = "accounts/admin_login.html"
