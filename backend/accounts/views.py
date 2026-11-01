from django.contrib.auth import authenticate, logout
from django.db import IntegrityError
from django.middleware.csrf import get_token, rotate_token
from django.utils.cache import patch_vary_headers
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AccountSession
from .security import limit_requests
from .serializers import AccountCredentials, RegistrationSerializer
from .services import active_sessions, register_account, revoke_session, start_session


def session_payload(request):
    user = request.user
    return {
        "user": {"id": user.pk, "username": user.username} if user.is_authenticated else None,
        "csrfToken": get_token(request),
    }


@method_decorator(csrf_protect, name="dispatch")
@method_decorator(sensitive_post_parameters(), name="dispatch")
class AccountAPIView(APIView):
    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["Cache-Control"] = "no-store"
        patch_vary_headers(response, ["Cookie"])
        return response


class SessionView(AccountAPIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response(session_payload(request))


class RegisterView(AccountAPIView):
    permission_classes = [AllowAny]

    @sensitive_variables()
    def post(self, request):
        if request.user.is_authenticated:
            raise PermissionDenied("Sign out before creating another account.")
        limit_requests(request, "register")
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user = register_account(request=request._request, **serializer.validated_data)
        except IntegrityError:
            raise ValidationError({"detail": "Unable to create an account with these details."}) from None
        # DRF cached the anonymous user during initial authentication.
        request.user = user
        return Response(session_payload(request), status=status.HTTP_201_CREATED)


class LoginView(AccountAPIView):
    permission_classes = [AllowAny]

    @sensitive_variables()
    def post(self, request):
        if request.user.is_authenticated:
            raise PermissionDenied("Sign out before signing in to another account.")
        limit_requests(request, "login")
        serializer = AccountCredentials(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(request=request._request, **serializer.validated_data)
        if user is None:
            return Response({"detail": "Invalid username or account password."}, status=400)
        start_session(request._request, user)
        request.user = user
        return Response(session_payload(request))


class LogoutView(AccountAPIView):
    def post(self, request):
        logout(request._request)
        request.user = request._request.user
        rotate_token(request)
        return Response(session_payload(request))


class SessionsView(AccountAPIView):
    def get(self, request):
        return Response({"sessions": [{
            "id": str(record.pk), "createdAt": record.created_at,
            "expiresAt": record.session.expire_date,
            "current": record.session_id == request.session.session_key,
        } for record in active_sessions(request.user)]})


class RevokeSessionView(AccountAPIView):
    def delete(self, request, session_id):
        try:
            revoke_session(user=request.user, session_id=session_id)
        except AccountSession.DoesNotExist:
            raise NotFound("Session not found.") from None
        return Response(status=status.HTTP_204_NO_CONTENT)
