"""Compare protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from application.objects import ProtocolRequests

from .base import BaseRequest


class CompareRequest(BaseRequest):
    """Compare protocol."""

    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.COMPARE
