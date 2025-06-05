"""Abandon request.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from typing import AsyncGenerator, ClassVar

from ldap_protocol.asn1parser import ASN1Row

from .base import BaseRequest


class AbandonRequest(BaseRequest):
    """Abandon protocol."""

    PROTOCOL_OP: ClassVar[int] = 16
    message_id: int

    @classmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> "AbandonRequest":  # noqa: ARG003
        """Create structure from ASN1Row dataclass list.

        Args:
            data (dict[str, list[ASN1Row]]): data

        Returns:
            AbandonRequest: Instance of AbandonRequest.
        """
        return cls(message_id=1)

    async def handle(self) -> AsyncGenerator:
        """Handle message with current user.

        Yields:
            AsyncGenerator: Async generator.
        """
        await asyncio.sleep(0)
        return
        yield  # type: ignore
