from io import BytesIO

from django.conf import settings
from rest_framework.exceptions import ParseError
from rest_framework.parsers import BaseParser, JSONParser


class BoundedJSONParser(BaseParser):
    """Bound streamed JSON too; Django's raw-body setting alone is insufficient."""
    media_type = "application/json"
    max_bytes = None

    def parse(self, stream, media_type=None, parser_context=None):
        limit = self.max_bytes if self.max_bytes is not None else settings.DATA_UPLOAD_MAX_MEMORY_SIZE
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ParseError("Request body too large.")
        try:
            return JSONParser().parse(BytesIO(data), media_type, parser_context)
        except RecursionError:
            raise ParseError("Invalid JSON document.") from None
