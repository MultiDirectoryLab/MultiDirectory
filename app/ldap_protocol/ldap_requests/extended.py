"""Extended request."""

from typing import ClassVar

from .base import BaseRequest


class ExtendedRequest(BaseRequest):
    """Extended protocol."""

    PROTOCOL_OP: ClassVar[int] = 23
    request_name: str
