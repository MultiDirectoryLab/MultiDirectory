"""Compare protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.objects import ProtocolRequests

from .base import BaseRequest


class CompareRequest(BaseRequest):
    """Compare protocol."""

    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.COMPARE

    async def to_event_data(self, session: AsyncSession) -> dict:
        return {}
