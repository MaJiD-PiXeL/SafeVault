from rest_framework import serializers

from .models import SecuritySettings, Vault, VaultEntry
from .validators import Base64Bytes


class StrictFields:
    def to_internal_value(self, data):
        writable = {name for name, field in self.fields.items() if not field.read_only}
        if not isinstance(data, dict) or set(data) - writable:
            raise serializers.ValidationError({"non_field_errors": ["Unexpected fields."]})
        return super().to_internal_value(data)


class CanonicalUUID(serializers.UUIDField):
    def to_internal_value(self, data):
        value = super().to_internal_value(data)
        if not isinstance(data, str) or str(value) != data:
            self.fail("invalid")
        return value


class EncodedBytes(serializers.CharField):
    def __init__(self, minimum, maximum, **kwargs):
        super().__init__(trim_whitespace=False, max_length=4 * ((maximum + 2) // 3),
                         validators=[Base64Bytes(minimum, maximum)], **kwargs)

    def to_internal_value(self, data):
        if not isinstance(data, str):
            self.fail("invalid")
        return super().to_internal_value(data)


class StrictInteger(serializers.IntegerField):
    def to_internal_value(self, data):
        if type(data) is not int:
            self.fail("invalid")
        return super().to_internal_value(data)


class VaultSerializer(StrictFields, serializers.ModelSerializer):
    id = CanonicalUUID()
    kdf_salt = EncodedBytes(16, 16)
    wrap_nonce = EncodedBytes(12, 12)
    wrapped_key = EncodedBytes(48, 48)

    class Meta:
        model = Vault
        fields = ["id", "format_version", "cipher", "kdf", "kdf_version", "kdf_memory_kib",
                  "kdf_iterations", "kdf_parallelism", "kdf_salt", "wrap_nonce", "wrapped_key",
                  "created_at", "updated_at"]
        read_only_fields = ["created_at", "updated_at"]


class EntryCreateSerializer(StrictFields, serializers.Serializer):
    id = CanonicalUUID()
    nonce = EncodedBytes(12, 12)
    ciphertext = EncodedBytes(17, 65552)


class EntryUpdateSerializer(StrictFields, serializers.Serializer):
    expected_revision = StrictInteger(min_value=1, max_value=2147483646)
    nonce = EncodedBytes(12, 12)
    ciphertext = EncodedBytes(17, 65552)


class EntryDeleteSerializer(StrictFields, serializers.Serializer):
    expected_revision = StrictInteger(min_value=1, max_value=2147483647)


class EntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = VaultEntry
        fields = ["id", "vault_id", "nonce", "ciphertext", "revision", "created_at", "updated_at"]


class SettingsSerializer(StrictFields, serializers.ModelSerializer):
    auto_lock_seconds = StrictInteger(min_value=60, max_value=3600)
    lock_on_hidden = serializers.BooleanField()

    class Meta:
        model = SecuritySettings
        fields = ["auto_lock_seconds", "lock_on_hidden"]

    def validate_lock_on_hidden(self, value):
        if type(self.initial_data["lock_on_hidden"]) is not bool:
            raise serializers.ValidationError("A boolean is required.")
        return value


class RestoreSerializer(StrictFields, serializers.Serializer):
    backup_id = CanonicalUUID()
    archive_digest = serializers.RegexField(r"^[0-9a-f]{64}$", max_length=64, trim_whitespace=False)
    entries = EntryCreateSerializer(many=True, allow_empty=False, max_length=5000)
