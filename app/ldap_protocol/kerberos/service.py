"""KerberosService: Implementation of Kerberos business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncIterator

import backoff
from dishka import AsyncContainer
from fastapi import Request
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.dialogue import LDAPSession, UserSchema
from ldap_protocol.identity.utils import authenticate_user
from ldap_protocol.kerberos.exceptions import (
    KerberosBaseDnNotFoundError,
    KerberosDependencyError,
    KerberosNotFoundError,
    KerberosUnavailableError,
)
from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.ldap_requests.contexts import LDAPAddRequestContext
from ldap_protocol.utils.queries import get_base_directories, get_dn_by_id

from .base import AbstractKadmin, KerberosState, KRBAPIError
from .ldap_structure import KRBLDAPStructureManager
from .schemas import AddRequests, KDCContext, KerberosAdminDnGroup, TaskStruct
from .template_render import KRBTemplateRenderer
from .utils import get_krb_server_state, set_state


class KerberosService:
    """Kerberos business logic coordinator for KDC and LDAP operations."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        kadmin: AbstractKadmin,
        krb_template_render: KRBTemplateRenderer,
        krb_ldap_manager: KRBLDAPStructureManager,
    ) -> None:
        """Initialize KerberosService dependencies.

        Args:
            session (AsyncSession): SQLAlchemy async session.
            settings (Settings): App settings.
            kadmin (AbstractKadmin): Kerberos admin interface.
            krb_template_render (KRBTemplateRenderer):
                Template renderer for Kerberos (IoC-injected).
            krb_ldap_manager (KRBLDAPStructureManager):
                LDAP structure manager for Kerberos (IoC-injected).

        """
        self._session = session
        self._settings = settings
        self._kadmin = kadmin
        self._template_render = krb_template_render
        self._ldap_manager = krb_ldap_manager

    async def setup_krb_catalogue(
        self,
        mail: str,
        krbadmin_password: SecretStr,
        ldap_session: LDAPSession,
        ctx: LDAPAddRequestContext,
    ) -> None:
        """Create Kerberos structure in the LDAP directory.

        Args:
            mail (str): Email for krbadmin.
            krbadmin_password (SecretStr): Password for krbadmin.
            ctx (LDAPAddRequestContext): context for add request.

        Raises:
            KerberosConflictError: On structure creation conflict.

        """
        ctx.ldap_session = ldap_session
        base_dn, _ = await self._get_base_dn()
        dns = self._build_kerberos_admin_dns(base_dn)
        add_requests = self._build_add_requests(
            dns,
            mail,
            krbadmin_password,
        )
        await self._ldap_manager.create_kerberos_structure(
            add_requests.group,
            add_requests.services,
            add_requests.krb_user,
            ctx,
        )

    async def _get_base_dn(self) -> tuple[str, str]:
        """Get LDAP root DN and domain."""
        base_dn_list = await get_base_directories(self._session)
        if not base_dn_list:
            raise KerberosBaseDnNotFoundError(
                "No base DN found in the LDAP directory."
            )
        return base_dn_list[0].path_dn, base_dn_list[0].name

    def _build_kerberos_admin_dns(self, base_dn: str) -> KerberosAdminDnGroup:
        """Build DN strings for Kerberos admin, services, and group.

        :param str base_dn: Base DN.
        :return KerberosAdminDnGroup:
            dataclass with DN for krbadmin, services_container, krbadmin_group.
        """
        krbadmin = f"cn=krbadmin,ou=users,{base_dn}"
        services_container = f"ou=services,{base_dn}"
        krbgroup = f"cn=krbadmin,cn=groups,{base_dn}"
        return KerberosAdminDnGroup(
            krbadmin_dn=krbadmin,
            services_container_dn=services_container,
            krbadmin_group_dn=krbgroup,
        )

    def _build_add_requests(
        self,
        dns: KerberosAdminDnGroup,
        mail: str,
        krbadmin_password: SecretStr,
    ) -> AddRequests:
        """Build AddRequest objects for group, services, and admin user.

        :param KerberosAdminDnGroup dns:
            DNs for krbadmin, services container, and group.
        :param str mail: Email for krbadmin.
        :param SecretStr krbadmin_password: Password for krbadmin.
        :return AddRequests:
            dataclass of AddRequest for group, services, and user.
        """
        group = AddRequest.from_dict(
            dns.krbadmin_group_dn,
            {
                "objectClass": ["group", "top", "posixGroup"],
                "groupType": ["-2147483646"],
                "instanceType": ["4"],
                "description": ["Kerberos administrator's group."],
                "gidNumber": ["800"],
            },
        )
        services = AddRequest.from_dict(
            dns.services_container_dn,
            {"objectClass": ["organizationalUnit", "top", "container"]},
        )
        krb_user = AddRequest.from_dict(
            dns.krbadmin_dn,
            password=krbadmin_password.get_secret_value(),
            attributes={
                "mail": [mail],
                "objectClass": [
                    "user",
                    "top",
                    "person",
                    "organizationalPerson",
                    "posixAccount",
                    "shadowAccount",
                    "inetOrgPerson",
                ],
                "loginShell": ["/bin/false"],
                "uidNumber": ["800"],
                "gidNumber": ["800"],
                "givenName": ["Kerberos Administrator"],
                "sn": ["krbadmin"],
                "uid": ["krbadmin"],
                "homeDirectory": ["/home/krbadmin"],
                "memberOf": [dns.krbadmin_group_dn],
                "sAMAccountName": ["krbadmin"],
                "userPrincipalName": ["krbadmin"],
                "displayName": ["Kerberos Administrator"],
            },
        )
        return AddRequests(
            group=group,
            services=services,
            krb_user=krb_user,
        )

    async def setup_kdc(
        self,
        krbadmin_password: str,
        admin_password: str,
        stash_password: str,
        user: UserSchema,
        request: Request,
    ) -> TaskStruct:
        """Set up KDC, generate configs, and return TaskStruct.

        Args:
            krbadmin_password (str): Password for krbadmin.
            admin_password (str): Password for admin.
            stash_password (str): Stash password.
            user (UserSchema): Current user.
            request (Request): FastAPI request (for DI container).

        Returns:
            tuple: (func, args, kwargs) for background task.

        Raises:
            KerberosDependencyError: On dependency/auth error.

        """
        try:
            context = await self._get_kdc_context()
            context.ldap_uri = self._settings.KRB5_LDAP_URI
            krb5_config = await self._template_render.render_krb5(context)
            kdc_config = await self._template_render.render_kdc(context)
            await self._authenticate_admin(user, admin_password)
            await self._kadmin.setup(
                domain=context.domain,
                admin_dn=await get_dn_by_id(user.directory_id, self._session),
                services_dn=context.services_container,
                krbadmin_dn=context.krbadmin,
                krbadmin_password=krbadmin_password,
                admin_password=admin_password,
                stash_password=stash_password,
                krb5_config=krb5_config,
                kdc_config=kdc_config,
                ldap_keytab_path=self._settings.KRB5_LDAP_KEYTAB,
            )
        except KRBAPIError as err:
            await self._ldap_manager.rollback_kerberos_structure(
                context.krbadmin,
                context.services_container,
                context.krbgroup,
            )
            await self._kadmin.reset_setup()
            raise KerberosDependencyError(str(err))
        else:
            await set_state(self._session, KerberosState.READY)
            await self._session.commit()
            return await self._schedule_principal_task(
                request,
                user,
                admin_password,
            )

    async def _get_kdc_context(self) -> KDCContext:
        """Build and return context for KDC setup/config rendering.

        :raises Exception: If base DN cannot be retrieved.
        :return KDCContext: dataclass with all required KDC context fields.
        """
        base_dn, domain = await self._get_base_dn()
        krbadmin = f"cn=krbadmin,ou=users,{base_dn}"
        krbgroup = f"cn=krbadmin,cn=groups,{base_dn}"
        services_container = f"ou=services,{base_dn}"
        return KDCContext(
            base_dn=base_dn,
            domain=domain,
            krbadmin=krbadmin,
            krbgroup=krbgroup,
            services_container=services_container,
            ldap_uri="",
        )

    async def _authenticate_admin(
        self,
        user: UserSchema,
        password: str,
    ) -> None:
        """Authenticate admin user for KDC setup.

        :param UserSchema user: User performing the setup.
        :param str password: Password for admin.
        :raises KerberosDependencyError: If authentication fails.
        :return None: None.
        """
        if not await authenticate_user(
            self._session,
            user.user_principal_name,
            password,
        ):
            raise KerberosDependencyError("Incorrect password")

    async def _schedule_principal_task(
        self,
        request: Request,
        user: UserSchema,
        password: str,
    ) -> TaskStruct:
        """Schedule background task for principal creation after KDC setup.

        :param Request request: FastAPI request (for DI container).
        :param UserSchema user: User for whom principal is created.
        :param str password: Password for admin.
        :return: tuple (func, args, kwargs) for background task.
        """
        container: AsyncContainer = request.state.dishka_container
        new_kadmin: AbstractKadmin = await container.get(AbstractKadmin)
        func = backoff.on_exception(
            backoff.fibo,
            Exception,
            max_tries=10,
            logger=None,
            raise_on_giveup=False,
        )(new_kadmin.add_principal)
        args = (
            user.user_principal_name.split("@")[0],
            password,
        )
        return TaskStruct(func=func, args=args)

    async def add_principal(self, primary: str, instance: str) -> None:
        """Create principal in Kerberos with given name.

        :param str primary: Principal primary name.
        :param str instance: Principal instance name.
        :raises KerberosDependencyError: On failed kadmin request.
        :return None: None.
        """
        try:
            principal_name = f"{primary}/{instance}"
            await self._kadmin.add_principal(principal_name, None)
        except KRBAPIError as exc:
            raise KerberosDependencyError(
                f"Error adding principal: {exc}"
            ) from exc

    async def rename_principal(
        self,
        principal_name: str,
        principal_new_name: str,
    ) -> None:
        """Rename principal in Kerberos with given name.

        :param str principal_name: Current principal name.
        :param str principal_new_name: New principal name.
        :raises KerberosDependencyError: On failed kadmin request.
        :return None: None.
        """
        try:
            await self._kadmin.rename_princ(principal_name, principal_new_name)
        except Exception as exc:
            raise KerberosDependencyError(
                f"Error renaming principal: {exc}"
            ) from exc

    async def reset_principal_pw(
        self,
        principal_name: str,
        new_password: str,
    ) -> None:
        """Reset principal password in Kerberos with given name.

        :param str principal_name: Principal name.
        :param str new_password: New password.
        :raises KerberosDependencyError: On failed kadmin request.
        :return None: None.
        """
        try:
            await self._kadmin.change_principal_password(
                principal_name,
                new_password,
            )
        except Exception as exc:
            raise KerberosDependencyError(
                f"Error resetting principal password: {exc}"
            ) from exc

    async def delete_principal(self, principal_name: str) -> None:
        """Delete principal in Kerberos with given name.

        :param str principal_name: Principal name.
        :raises KerberosDependencyError: On failed kadmin request.
        :return None: None.
        """
        try:
            await self._kadmin.del_principal(principal_name)
        except Exception as exc:
            raise KerberosDependencyError(
                f"Error deleting principal: {exc}"
            ) from exc

    async def ktadd(
        self,
        names: list[str],
    ) -> tuple[AsyncIterator[bytes], TaskStruct]:
        """Generate keytab and return (aiter_bytes, TaskStruct).

        :param list[str] names: List of principal names.
        :raises KerberosNotFoundError: If principal not found.
        :return tuple: (aiter_bytes, (func, args, kwargs)).
        """
        try:
            response = await self._kadmin.ktadd(names)
        except KRBAPIError:
            raise KerberosNotFoundError("Principal not found")
        aiter_bytes = response.aiter_bytes()
        func = response.aclose
        return aiter_bytes, TaskStruct(func=func)

    async def get_status(self) -> KerberosState:
        """Get Kerberos server state (db + actual server).

        :raises KerberosUnavailableError: If server is unavailable.
        :return KerberosState: Current Kerberos state.
        """
        db_state = await get_krb_server_state(self._session)
        try:
            server_state = await self._kadmin.get_status()
        except KRBAPIError:
            raise KerberosUnavailableError("Kerberos server unavailable")
        if server_state is False and db_state == KerberosState.READY:
            return KerberosState.WAITING_FOR_RELOAD
        return db_state
