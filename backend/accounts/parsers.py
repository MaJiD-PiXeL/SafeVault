from io import BytesIO

from django.conf import settings
from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser


class BoundedJSONParser(JSONParser):
    """Bound streamed JSON too; Django's raw-body setting alone is insufficient."""
    def parse(self, stream, media_type=None, parser_context=None):
        data = stream.read(settings.DATA_UPLOAD_MAX_MEMORY_SIZE + 1)
        if len(data) > settings.DATA_UPLOAD_MAX_MEMORY_SIZE:
            raise ParseError("Request body too large.")
        try:
            return super().parse(BytesIO(data), media_type, parser_context)
        except RecursionError:
            raise ParseError("Invalid JSON document.") from None
