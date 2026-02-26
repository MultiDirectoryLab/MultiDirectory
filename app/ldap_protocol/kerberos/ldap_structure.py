"""Kerberos LDAP structure manager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Directory
from ldap_protocol.kerberos.exceptions import KerberosConflictError
from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.ldap_requests.contexts import LDAPAddRequestContext
from ldap_protocol.roles.access_manager import AccessManager
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.utils.queries import get_filter_from_path
from repo.pg.tables import queryable_attr as qa


class KRBLDAPStructureManager:
    """Manager for Kerberos-related LDAP structure operations."""

    def __init__(
        self,
        session: AsyncSession,
        role_use_case: RoleUseCase,
        access_manager: AccessManager,
    ) -> None:
        """Initialize KRBLDAPStructureManager with a database session.

        :param AsyncSession session: SQLAlchemy async session.
        :param RoleUseCase role_use_case: Role use case for managing roles.
        :return None.
        """
        self._session = session
        self._role_use_case = role_use_case
        self._access_manager = access_manager

    async def create_kerberos_structure(
        self,
        group: AddRequest,
        krb_user: AddRequest,
        ctx: LDAPAddRequestContext,
    ) -> None:
        """Create Kerberos structure in the LDAP directory.

        :param AddRequest group: AddRequest for Kerberos group.
        :param AddRequest krb_user: AddRequest for Kerberos admin user.
        :param LDAPAddRequestContext ctx: LDAP request context.
        :raises Exception: On structure creation error.
        :return None.
        """
        async with self._session.begin_nested():
            group_result = await anext(group.handle(ctx))
            if group_result.result_code != 0:
                raise KerberosConflictError("Group error")

        async with self._session.begin_nested():
            await self._role_use_case.create_kerberos_system_role()
            await self._role_use_case.add_read_only_role_to_krbadmin_group()
            user_result = await anext(krb_user.handle(ctx))
            if user_result.result_code != 0:
                raise KerberosConflictError("User error")

    async def rollback_kerberos_structure(
        self,
        krbadmin: str,
        krbgroup: str,
    ) -> None:
        """Rollback Kerberos structure in the LDAP directory.

        :param str krbadmin: DN for Kerberos admin user.
        :param str krbgroup: DN for Kerberos group.
        :return None.
        """
        directories_query = select(Directory).where(
            or_(
                get_filter_from_path(krbadmin),
                get_filter_from_path(krbgroup),
            ),
        )
        directories = await self._session.scalars(directories_query)
        if directories:
            q = qa(Directory.id).in_([dir_.id for dir_ in directories])
            await self._session.execute(delete(Directory).where(q))

        await self._role_use_case.delete_kerberos_system_role()
