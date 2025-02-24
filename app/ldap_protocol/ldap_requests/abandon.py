"""Abandon request.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from typing import AsyncGenerator, ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.objects import ProtocolRequests

from .base import BaseRequest


class AbandonRequest(BaseRequest):
    """Abandon protocol."""

    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.ABANDON
    message_id: int

    @classmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> "AbandonRequest":  # noqa: ARG003
        """Create structure from ASN1Row dataclass list."""
        return cls(message_id=1)

    async def handle(self) -> AsyncGenerator:
        """Handle message with current user."""
        await asyncio.sleep(0)
        return
        yield  # type: ignore

    async def to_event_data(self, session: AsyncSession) -> dict:
        return {}
