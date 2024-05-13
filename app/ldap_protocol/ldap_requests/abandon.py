"""Abandon request.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from typing import AsyncGenerator, ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import Session

from .base import BaseRequest


class AbandonRequest(BaseRequest):
    """Abandon protocol."""

    PROTOCOL_OP: ClassVar[int] = 16
    message_id: int

    @classmethod
    def from_data(cls, data: ASN1Row) -> 'AbandonRequest':
        """Create structure from ASN1Row dataclass list."""
        return cls(message_id=1)

    async def handle(
            self, _: Session,
            __: AsyncSession) -> AsyncGenerator:
        """Handle message with current user."""
        await asyncio.sleep(0)
        return
        yield  # type: ignore
