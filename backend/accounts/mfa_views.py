from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_variables
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from . import mfa
from .models import SecondFactor
from .security import limit_requests
from .serializers import StrictAccountFields
from .views import AccountAPIView


class FactorAction(StrictAccountFields):
    action = serializers.ChoiceField(choices=["begin", "confirm", "disable", "regenerate"])
    password = serializers.CharField(max_length=1024, trim_whitespace=False, write_only=True)
    code = serializers.CharField(max_length=64, required=False, default="", allow_blank=True, trim_whitespace=False, write_only=True)


@method_decorator(sensitive_variables(), name="dispatch")
class SecondFactorView(AccountAPIView):
    def get(self, request):
        factor = SecondFactor.objects.filter(user=request.user, enabled=True).first()
        return Response({"enabled": bool(factor), "recoveryCodesRemaining": len(factor.recovery_hashes) if factor else 0})

    def post(self, request):
        limit_requests(request, "mfa-manage", subject=str(request.user.pk))
        serializer = FactorAction(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self.perform(request, serializer.validated_data)

    @transaction.atomic
    def perform(self, request, data):
        user = get_user_model().objects.select_for_update().get(pk=request.user.pk)
        if not user.is_active or not user.check_password(data["password"]):
            raise ValidationError({"detail": "Check your account password and verification code."})
        if data["action"] == "begin":
            setup = mfa.begin(user)
            if setup is None:
                raise ValidationError({"detail": "Two-step verification is already enabled."})
            return Response(setup)
        factor = SecondFactor.objects.filter(user=user).first()
        if data["action"] == "confirm":
            codes = mfa.enable(factor, data["code"]) if factor else None
            if codes is not None:
                mfa.mark_verified(request, factor)
                mfa.revoke_other_sessions(user, request.session.session_key)
                return Response({"recoveryCodes": codes})
        elif data["action"] == "regenerate" and factor and factor.enabled and mfa.consume(factor, data["code"]):
            codes = mfa.new_recovery_codes(factor)
            mfa.mark_verified(request, factor)
            mfa.revoke_other_sessions(user, request.session.session_key)
            return Response({"recoveryCodes": codes})
        elif data["action"] == "disable" and factor and factor.enabled and mfa.consume(factor, data["code"]):
            factor.delete()
            request.session.pop(mfa.SESSION_PROOF, None)
            mfa.revoke_other_sessions(user, request.session.session_key)
            return Response({"enabled": False})
        raise ValidationError({"detail": "Check your verification code or restart expired setup."})
