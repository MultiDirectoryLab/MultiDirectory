"""Compare protocol."""

from typing import ClassVar

from .base import BaseRequest


class CompareRequest(BaseRequest):
    """Compare protocol."""

    PROTOCOL_OP: ClassVar[int] = 14
