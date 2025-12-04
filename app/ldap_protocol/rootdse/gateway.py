"""LDAP SQLAlchemy gw for handle requests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Directory


class SADomainGateway:
    """RootDSE gw."""

    def __init__(self, session: AsyncSession) -> None:
        """Setu up gw."""
        self._session = session

    async def get_domain(self) -> Directory:
        domain_query = select(Directory).filter_by(object_class="domain")
        return (await self._session.scalars(domain_query)).one()
