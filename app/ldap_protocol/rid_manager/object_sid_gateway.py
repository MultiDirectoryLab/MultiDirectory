"""Object SID gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Attribute, Directory
from ldap_protocol.rid_manager.exceptions import (
    RIDManagerDomainIdentifierNotFoundError,
    RIDManagerObjectSIDNotFoundError,
)
from repo.pg.tables import queryable_attr as qa


class ObjectSIDGateway:
    """Object SID gateway."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Object SID gateway."""
        self._session = session

    async def get(self, directory: Directory) -> str:
        """Get object SID."""
        query = await self._session.scalar(
            select(Attribute).where(
                qa(Attribute.directory_id) == directory.id,
                qa(Attribute.name) == "objectSid",
            ),
        )
        if not (query and query.value):
            raise RIDManagerObjectSIDNotFoundError("object SID not found")

        return query.value

    async def add(self, directory: Directory, object_sid: str) -> None:
        """Add object SID."""
        self._session.add(
            Attribute(
                name="objectSid",
                value=object_sid,
                directory_id=directory.id,
            ),
        )

    async def get_domain_identifier(self, domain: Directory) -> str:
        """Get domain identifier.

        :return: Domain identifier
        """
        query = await self._session.scalar(
            select(Attribute).where(
                qa(Attribute.name) == "DomainIdentifier",
                qa(Attribute.directory_id) == domain.id,
            ),
        )

        if not query or not query.value:
            raise RIDManagerDomainIdentifierNotFoundError(
                "domain identifier not found",
            )

        return query.value
