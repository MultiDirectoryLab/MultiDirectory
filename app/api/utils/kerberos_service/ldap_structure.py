"""Kerberos LDAP structure manager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.policies.access_policy import create_access_policy
from ldap_protocol.utils.queries import get_filter_from_path
from models import AccessPolicy, Directory


class LDAPStructureManager:
    """Manager for Kerberos-related LDAP structure operations."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize LDAPStructureManager with a database session.

        :param AsyncSession session: SQLAlchemy async session.
        :return None.
        """
        self._session = session

    async def create_kerberos_structure(
        self,
        group: AddRequest,
        services: AddRequest,
        rkb_user: AddRequest,
        ldap_session: LDAPSession,
        kadmin: AbstractKadmin,
        entity_type_dao: EntityTypeDAO,
        services_container: str,
        krbgroup: str,
    ) -> None:
        """Create Kerberos structure in the LDAP directory.

        :param AddRequest group: AddRequest for Kerberos group.
        :param AddRequest services: AddRequest for services container.
        :param AddRequest rkb_user: AddRequest for Kerberos admin user.
        :param LDAPSession ldap_session: LDAP session.
        :param AbstractKadmin kadmin: Kerberos admin interface.
        :param EntityTypeDAO entity_type_dao: DAO for entity types.
        :param str services_container: DN for services container.
        :param str krbgroup: DN for Kerberos group.
        :raises Exception: On structure creation error.
        :return None.
        """
        async with self._session.begin_nested():
            results = (
                await anext(
                    services.handle(
                        self._session, ldap_session, kadmin, entity_type_dao
                    )
                ),
                await anext(
                    group.handle(
                        self._session, ldap_session, kadmin, entity_type_dao
                    )
                ),
                await anext(
                    rkb_user.handle(
                        self._session, ldap_session, kadmin, entity_type_dao
                    )
                ),
            )
            await self._session.flush()
            if not all(result.result_code == 0 for result in results):
                await self._session.rollback()
                raise Exception(
                    "Error creating Kerberos structure in directory"
                )
            await create_access_policy(
                name="Kerberos Access Policy",
                can_add=True,
                can_modify=True,
                can_read=True,
                can_delete=True,
                grant_dn=services_container,
                groups=[krbgroup],
                session=self._session,
            )
            await self._session.commit()

    async def rollback_kerberos_structure(
        self,
        krbadmin: str,
        services_container: str,
        krbgroup: str,
    ) -> None:
        """Rollback Kerberos structure in the LDAP directory.

        :param str krbadmin: DN for Kerberos admin user.
        :param str services_container: DN for services container.
        :param str krbgroup: DN for Kerberos group.
        :return None.
        """
        direstories_query = select(Directory).where(
            or_(
                get_filter_from_path(krbadmin),
                get_filter_from_path(services_container),
                get_filter_from_path(krbgroup),
            )
        )
        direstories = await self._session.scalars(direstories_query)
        if direstories:
            await self._session.execute(
                delete(Directory).where(
                    Directory.id.in_([dir_.id for dir_ in direstories])
                )
            )
        await self._session.execute(
            delete(AccessPolicy).where(
                AccessPolicy.name == "Kerberos Access Policy"
            )
        )
