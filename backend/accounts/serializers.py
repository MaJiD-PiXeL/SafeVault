from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers


class StrictAccountFields(serializers.Serializer):
    def to_internal_value(self, data):
        if not isinstance(data, dict) or set(data) - set(self.fields):
            raise serializers.ValidationError({"non_field_errors": ["Unexpected account fields."]})
        if any(name in data and not isinstance(data[name], str) for name in self.fields):
            raise serializers.ValidationError({"non_field_errors": ["Account fields must be text."]})
        data = {**data}
        if isinstance(data.get("username"), str):
            data["username"] = data["username"].strip().lower()
        return super().to_internal_value(data)


class AccountCredentials(StrictAccountFields):
    username = serializers.RegexField(r"^[a-z0-9][a-z0-9_.-]{2,49}$", max_length=50)
    password = serializers.CharField(max_length=1024, trim_whitespace=False, write_only=True)


class RegistrationSerializer(AccountCredentials):
    def validate(self, data):
        try:
            validate_password(data["password"], get_user_model()(username=data["username"]))
        except DjangoValidationError as error:
            raise serializers.ValidationError({"password": error.messages}) from None
        return data


class RecoveryEmailSerializer(StrictAccountFields):
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(max_length=1024, trim_whitespace=False, write_only=True)


class RecoveryRequestSerializer(StrictAccountFields):
    username = serializers.RegexField(r"^[a-z0-9][a-z0-9_.-]{2,49}$", max_length=50)


class RecoveryLinkSerializer(RecoveryRequestSerializer):
    token = serializers.RegexField(r"\A[0-9a-z]{1,13}-[0-9a-f]{32}\Z", max_length=46,
                                   trim_whitespace=False, write_only=True)


class ResetPasswordSerializer(RecoveryLinkSerializer):
    password = serializers.CharField(max_length=1024, trim_whitespace=False, write_only=True)
