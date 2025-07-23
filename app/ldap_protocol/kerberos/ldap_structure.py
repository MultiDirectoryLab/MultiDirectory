"""Kerberos LDAP structure manager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos.exceptions import KerberosConflictError
from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.roles.access_manager import AccessManager
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.utils.queries import get_filter_from_path
from models import Directory

from .base import AbstractKadmin


class KRBLDAPStructureManager:
    """Manager for Kerberos-related LDAP structure operations."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize KRBLDAPStructureManager with a database session.

        :param AsyncSession session: SQLAlchemy async session.
        :return None.
        """
        self._session = session

    async def create_kerberos_structure(
        self,
        group: AddRequest,
        services: AddRequest,
        krb_user: AddRequest,
        ldap_session: LDAPSession,
        kadmin: AbstractKadmin,
        entity_type_dao: EntityTypeDAO,
        access_manager: AccessManager,
        role_use_case: RoleUseCase,
        base_dn: str,
    ) -> None:
        """Create Kerberos structure in the LDAP directory.

        :param AddRequest group: AddRequest for Kerberos group.
        :param AddRequest services: AddRequest for services container.
        :param AddRequest krb_user: AddRequest for Kerberos admin user.
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
                        self._session,
                        ldap_session,
                        kadmin,
                        entity_type_dao,
                        access_manager,
                        role_use_case,
                    )
                ),
                await anext(
                    group.handle(
                        self._session,
                        ldap_session,
                        kadmin,
                        entity_type_dao,
                        access_manager,
                        role_use_case,
                    )
                ),
                await anext(
                    krb_user.handle(
                        self._session,
                        ldap_session,
                        kadmin,
                        entity_type_dao,
                        access_manager,
                        role_use_case,
                    )
                ),
            )
            await self._session.flush()

            if not all(result.result_code == 0 for result in results):
                await self._session.rollback()
                raise KerberosConflictError(
                    "Error creating Kerberos structure in directory"
                )
            await role_use_case.create_kerberos_system_role(base_dn)
            await self._session.commit()

    async def rollback_kerberos_structure(
        self,
        krbadmin: str,
        services_container: str,
        krbgroup: str,
        role_use_case: RoleUseCase,
    ) -> None:
        """Rollback Kerberos structure in the LDAP directory.

        :param str krbadmin: DN for Kerberos admin user.
        :param str services_container: DN for services container.
        :param str krbgroup: DN for Kerberos group.
        :return None.
        """
        directories_query = select(Directory).where(
            or_(
                get_filter_from_path(krbadmin),
                get_filter_from_path(services_container),
                get_filter_from_path(krbgroup),
            )
        )
        directories = await self._session.scalars(directories_query)
        if directories:
            await self._session.execute(
                delete(Directory).where(
                    Directory.id.in_([dir_.id for dir_ in directories])
                )
            )
        await role_use_case.delete_kerberos_system_role()
