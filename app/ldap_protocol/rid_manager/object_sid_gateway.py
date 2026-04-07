"""Object SID gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Attribute
from ldap_protocol.rid_manager.exceptions import (
    RIDManagerDomainIdentifierNotFoundError,
    RIDManagerObjectSIDNotFoundError,
)
from ldap_protocol.utils.async_cache import domain_identifier_cache
from repo.pg.tables import queryable_attr as qa


class ObjectSIDGateway:
    """Object SID gateway."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Object SID gateway."""
        self._session = session

    async def get(self, directory_id: int) -> str:
        """Get object SID."""
        query = await self._session.scalar(
            select(Attribute).where(
                qa(Attribute.directory_id) == directory_id,
                qa(Attribute.name) == "objectSid",
            ),
        )
        if not (query and query.value):
            raise RIDManagerObjectSIDNotFoundError("object SID not found")

        return query.value

    async def add(self, directory_id: int, object_sid: str) -> None:
        """Add object SID."""
        self._session.add(
            Attribute(
                name="objectSid",
                value=object_sid,
                directory_id=directory_id,
            ),
        )

    async def get_domain_identifier(self) -> str:
        """Get domain identifier (cached ``Attribute.value`` string)."""
        return await domain_identifier_cache.get_or_load(
            self._load_domain_identifier_value,
        )

    async def _load_domain_identifier_value(self) -> str:
        query = await self._session.scalar(
            select(Attribute).where(
                qa(Attribute.name) == "DomainIdentifier",
            ),
        )

        if not query or not query.value:
            raise RIDManagerDomainIdentifierNotFoundError(
                "domain identifier not found",
            )

        return query.value
