from django.core.exceptions import ValidationError as ModelValidationError
from django.db import IntegrityError, transaction
from rest_framework.exceptions import APIException, NotFound, ValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

from accounts.views import AccountAPIView
from accounts.parsers import BoundedJSONParser
from accounts.security import limit_requests
from .models import RestoreReceipt, SecuritySettings, Vault, VaultEntry
from .serializers import (EntryCreateSerializer, EntryDeleteSerializer, EntrySerializer,
                          EntryUpdateSerializer, RestoreSerializer, SettingsSerializer, VaultSerializer)
from .services import NonceConflict, RevisionConflict, create_entry, create_vault, delete_entry, list_entries, restore_entries, update_entry


class Conflict(APIException):
    status_code = 409
    default_detail = "The record changed or the nonce was used. Refresh before saving again."


class VaultAPIView(AccountAPIView):
    def handle_exception(self, exc):
        if isinstance(exc, (Vault.DoesNotExist, VaultEntry.DoesNotExist)):
            exc = NotFound("Vault item not found.")
        elif isinstance(exc, (RevisionConflict, NonceConflict, IntegrityError)):
            exc = Conflict()
        elif isinstance(exc, ModelValidationError):
            exc = ValidationError({"detail": "Invalid encrypted data or storage limit reached."})
        return super().handle_exception(exc)


class VaultsView(VaultAPIView):
    def get(self, request):
        vaults = Vault.objects.for_user(request.user).order_by("created_at", "id")
        return Response({"vaults": VaultSerializer(vaults, many=True).data})

    def post(self, request):
        serializer = VaultSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        vault = create_vault(user=request.user, vault_id=data["id"], kdf_salt=data["kdf_salt"],
                             wrap_nonce=data["wrap_nonce"], wrapped_key=data["wrapped_key"])
        return Response(VaultSerializer(vault).data, status=201)


class EntryPagination(PageNumberPagination):
    page_size = 50


class EntriesView(VaultAPIView):
    def get(self, request, vault_id):
        entries = list_entries(user=request.user, vault_id=vault_id)
        paginator = EntryPagination()
        page = paginator.paginate_queryset(entries, request)
        return paginator.get_paginated_response(EntrySerializer(page, many=True).data)

    def post(self, request, vault_id):
        # Scope ownership before examining another account's identifiers.
        Vault.objects.for_user(request.user).get(pk=vault_id)
        serializer = EntryCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        entry = create_entry(user=request.user, vault_id=vault_id, entry_id=data["id"],
                             nonce=data["nonce"], ciphertext=data["ciphertext"])
        return Response(EntrySerializer(entry).data, status=201)


class EntryView(VaultAPIView):
    def owned_entry(self, request, vault_id, entry_id):
        return VaultEntry.objects.for_user(request.user).get(pk=entry_id, vault_id=vault_id)

    def get(self, request, vault_id, entry_id):
        return Response(EntrySerializer(self.owned_entry(request, vault_id, entry_id)).data)

    def patch(self, request, vault_id, entry_id):
        self.owned_entry(request, vault_id, entry_id)
        serializer = EntryUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entry = update_entry(user=request.user, entry_id=entry_id, **serializer.validated_data)
        return Response(EntrySerializer(entry).data)

    def delete(self, request, vault_id, entry_id):
        self.owned_entry(request, vault_id, entry_id)
        serializer = EntryDeleteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        delete_entry(user=request.user, entry_id=entry_id, **serializer.validated_data)
        return Response(status=204)


class SecuritySettingsView(VaultAPIView):
    def get(self, request):
        preferences = SecuritySettings.objects.filter(user=request.user).first() or SecuritySettings(user=request.user)
        return Response(SettingsSerializer(preferences).data)

    @transaction.atomic
    def patch(self, request):
        preferences, _ = SecuritySettings.objects.get_or_create(user=request.user)
        preferences = SecuritySettings.objects.select_for_update().get(pk=preferences.pk)
        serializer = SettingsSerializer(preferences, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class RestoreJSONParser(BoundedJSONParser):
    # Only this authenticated, rate-limited endpoint accepts larger encrypted batches.
    max_bytes = 36 * 1024 * 1024


def receipt_data(receipt, already_restored=True):
    return {"backup_id": str(receipt.backup_id), "archive_digest": receipt.archive_digest,
            "entry_count": receipt.entry_count, "already_restored": already_restored}


class RestoreView(VaultAPIView):
    parser_classes = [RestoreJSONParser]

    def post(self, request, vault_id):
        Vault.objects.for_user(request.user).get(pk=vault_id)
        limit_requests(request, "restore")  # Before parsing/hash/validation of a large body.
        serializer = RestoreSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        receipt, repeated = restore_entries(user=request.user, vault_id=vault_id, **serializer.validated_data)
        return Response(receipt_data(receipt, repeated), status=200 if repeated else 201)


class RestoreReceiptView(VaultAPIView):
    def get(self, request, vault_id, backup_id):
        vault = Vault.objects.for_user(request.user).get(pk=vault_id)
        receipt = RestoreReceipt.objects.filter(vault=vault, backup_id=backup_id).first()
        if not receipt:
            raise NotFound("Restore not found.")
        return Response(receipt_data(receipt))
