from django.core.exceptions import ValidationError as DjangoValidationError
from django.views.decorators.debug import sensitive_variables
from rest_framework.exceptions import Throttled, ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import PasswordResetRequest, RecoveryEmail
from .recovery import (EmailDeliveryError, IncorrectAccountPassword, InvalidRecoveryLink,
                       RecoveryEmailAlreadyVerified, enroll_recovery_email, link_origin,
                       reset_account_password, send_recovery_link, verify_recovery_email)
from .security import limit_requests
from .serializers import (RecoveryEmailSerializer, RecoveryLinkSerializer, RecoveryRequestSerializer,
                          ResetPasswordSerializer)
from .views import AccountAPIView


class RecoveryEmailView(AccountAPIView):
    def get(self, request):
        address = RecoveryEmail.objects.filter(user=request.user).first()
        return Response({"email": address.email if address else None, "verified": bool(address and address.verified_at)})

    @sensitive_variables()
    def post(self, request):
        limit_requests(request, "recovery-enroll")
        limit_requests(request, "recovery-enroll-user", subject=request.user.pk)
        serializer = RecoveryEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            link_origin()
            limit_requests(request, "recovery-enroll-email", subject=serializer.validated_data["email"].casefold())
            user = enroll_recovery_email(user=request.user, **serializer.validated_data)
            send_recovery_link(user, verify=True)
        except IncorrectAccountPassword:
            raise ValidationError({"detail": "Incorrect account password."}) from None
        except RecoveryEmailAlreadyVerified:
            return Response({"detail": "A recovery email is already verified."}, status=409)
        except EmailDeliveryError:
            return Response({"detail": "Verification email could not be sent. Try again later."}, status=503)
        return Response(status=204)


class VerifyRecoveryEmailView(AccountAPIView):
    permission_classes = [AllowAny]

    @sensitive_variables()
    def post(self, request):
        limit_requests(request, "recovery-confirm")
        serializer = RecoveryLinkSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            verify_recovery_email(**serializer.validated_data)
        except InvalidRecoveryLink:
            raise ValidationError({"detail": "This verification link is invalid or expired."}) from None
        return Response(status=204)


class RequestPasswordResetView(AccountAPIView):
    permission_classes = [AllowAny]

    @sensitive_variables()
    def post(self, request):
        limit_requests(request, "recovery-request")
        serializer = RecoveryRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data["username"]
        try:
            limit_requests(request, "recovery-request-user", subject=username)
        except Throttled:
            pass
        else:
            # The HTTP request does not look up users or wait for email delivery.
            PasswordResetRequest.objects.get_or_create(username=username)
        return Response({"accepted": True}, status=202)


class ResetAccountPasswordView(AccountAPIView):
    permission_classes = [AllowAny]

    @sensitive_variables()
    def post(self, request):
        limit_requests(request, "recovery-confirm")
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            reset_account_password(**serializer.validated_data)
        except InvalidRecoveryLink:
            raise ValidationError({"detail": "This password reset link is invalid or expired."}) from None
        except DjangoValidationError as error:
            raise ValidationError({"password": error.messages}) from None
        return Response(status=204)
