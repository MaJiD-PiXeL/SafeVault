"""Validate transport encoding, never decrypt vault data on the server."""
import base64
import binascii

from django.core.exceptions import ValidationError
from django.utils.deconstruct import deconstructible


@deconstructible
class Base64Bytes:
    def __init__(self, minimum, maximum):
        self.minimum = minimum
        self.maximum = maximum

    def __call__(self, value):
        if not isinstance(value, str) or len(value) > 4 * ((self.maximum + 2) // 3):
            raise ValidationError("Invalid encoded data.", code="invalid_encoding")
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            raise ValidationError("Invalid encoded data.", code="invalid_encoding") from None
        if (
            not self.minimum <= len(decoded) <= self.maximum
            or base64.b64encode(decoded).decode("ascii") != value
        ):
            raise ValidationError("Invalid encoded data.", code="invalid_encoding")
