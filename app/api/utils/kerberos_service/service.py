"""KerberosService: Implementation of Kerberos business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncIterator

import backoff
from fastapi import Request
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from api.auth.oauth2 import authenticate_user
from api.main.schema import KerberosSetupRequest
from api.utils.exceptions import (
    KerberosDependencyError,
    KerberosNotFoundError,
    KerberosUnavailableError,
)
from config import Settings
from ldap_protocol.dialogue import LDAPSession, UserSchema
from ldap_protocol.kerberos import (
    AbstractKadmin,
    KerberosState,
    KRBAPIError,
    get_krb_server_state,
    set_state,
)
from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.utils.queries import get_base_directories, get_dn_by_id

from .ann import AddRequests, KDCContext, KerberosAdminDnGroup
from .ldap_structure import LDAPStructureManager
from .template_render import TemplateRenderer


class KerberosService:
    """Kerberos business logic coordinator for KDC and LDAP operations."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        kadmin: AbstractKadmin,
    ) -> None:
        """Initialize KerberosService dependencies.

        Args:
            session (AsyncSession): SQLAlchemy async session.
            settings (Settings): App settings.
            kadmin (AbstractKadmin): Kerberos admin interface.

        """
        self._session = session
        self._settings = settings
        self._kadmin = kadmin
        self._template_render = TemplateRenderer(settings.TEMPLATES)
        self._ldap_manager = LDAPStructureManager(session)

    async def setup_krb_catalogue(
        self,
        mail: str,
        krbadmin_password: SecretStr,
        ldap_session: LDAPSession,
        entity_type_dao: EntityTypeDAO,
    ) -> None:
        """Create Kerberos structure in the LDAP directory.

        Args:
            mail (str): Email for krbadmin.
            krbadmin_password (SecretStr): Password for krbadmin.
            ldap_session (LDAPSession): LDAP session.
            entity_type_dao (EntityTypeDAO): DAO for entity types.

        Raises:
            KerberosConflictError: On structure creation conflict.

        """
        base_dn, _ = await self._get_base_dn()
        dns = self._build_kerberos_admin_dns(base_dn)
        group, services, krb_user = self._build_add_requests(
            dns.krbadmin_dn,
            dns.services_container_dn,
            dns.krbadmin_group_dn,
            mail,
            krbadmin_password,
        )
        await self._ldap_manager.create_kerberos_structure(
            group,
            services,
            krb_user,
            ldap_session,
            self._kadmin,
            entity_type_dao,
            dns.services_container_dn,
            dns.krbadmin_group_dn,
        )

    async def _get_base_dn(self) -> tuple[str, str]:
        """Get the base distinguished name (DN) for the directory.

        :raises Exception: If base DN cannot be retrieved.
        :return str: Base DN string.
        """
        base_dn_list = await get_base_directories(self._session)
        return base_dn_list[0].path_dn, base_dn_list[0].name

    def _build_kerberos_admin_dns(self, base_dn: str) -> KerberosAdminDnGroup:
        """Build DN strings for Kerberos admin, services, and group.

        :param str base_dn: Base DN.
        :return KerberosAdminDnGroup: NamedTuple с DN для krbadmin, services_container, krbadmin_group.
        """
        krbadmin = f"cn=krbadmin,ou=users,{base_dn}"
        services_container = f"ou=services,{base_dn}"
        krbgroup = f"cn=krbadmin,cn=groups,{base_dn}"
        return KerberosAdminDnGroup(krbadmin, services_container, krbgroup)

    def _build_add_requests(
        self,
        krbadmin_dn: str,
        services_container: str,
        krbgroup: str,
        mail: str,
        krbadmin_password: SecretStr,
    ) -> AddRequests:
        """Build AddRequest objects for group, services, and admin user.

        :param str krbadmin_dn: DN for krbadmin user.
        :param str services_container: DN for services container.
        :param str krbgroup: DN for krbadmin group.
        :param str mail: Email for krbadmin.
        :param SecretStr krbadmin_password: Password for krbadmin.
        :return AddRequests: Tuple of AddRequest for group, services, and user.
        """
        group = AddRequest.from_dict(
            krbgroup,
            {
                "objectClass": ["group", "top", "posixGroup"],
                "groupType": ["-2147483646"],
                "instanceType": ["4"],
                "description": ["Kerberos administrator's group."],
                "gidNumber": ["800"],
            },
        )
        services = AddRequest.from_dict(
            services_container,
            {"objectClass": ["organizationalUnit", "top", "container"]},
        )
        krb_user = AddRequest.from_dict(
            krbadmin_dn,
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
                "memberOf": [krbgroup],
                "sAMAccountName": ["krbadmin"],
                "userPrincipalName": ["krbadmin"],
                "displayName": ["Kerberos Administrator"],
            },
        )
        return group, services, krb_user

    async def setup_kdc(
        self,
        data: KerberosSetupRequest,
        user: UserSchema,
        request: Request,
    ) -> BackgroundTask:
        """Set up KDC, generate configs, and return a background task.

        Args:
            data (KerberosSetupRequest): KDC setup request data.
            user (UserSchema): Current user.
            request (Request): FastAPI request (for DI container).

        Returns:
            BackgroundTask: Task for principal creation.

        Raises:
            KerberosDependencyError: On dependency/auth error.

        """
        try:
            context = await self._get_kdc_context()
            context["ldap_uri"] = self._settings.KRB5_LDAP_URI
            krb5_config = await self._template_render.render_krb5(context)
            kdc_config = await self._template_render.render_kdc(context)
            await self._authenticate_admin(user, data)
            await self._kadmin.setup(
                domain=context["domain"],
                admin_dn=await get_dn_by_id(user.directory_id, self._session),
                services_dn=context["services_container"],
                krbadmin_dn=context["krbadmin"],
                krbadmin_password=data.krbadmin_password.get_secret_value(),
                admin_password=data.admin_password.get_secret_value(),
                stash_password=data.stash_password.get_secret_value(),
                krb5_config=krb5_config,
                kdc_config=kdc_config,
                ldap_keytab_path=self._settings.KRB5_LDAP_KEYTAB,
            )
        except KRBAPIError as err:
            await self._ldap_manager.rollback_kerberos_structure(
                context["krbadmin"],
                context["services_container"],
                context["krbgroup"],
            )
            await self._kadmin.reset_setup()
            raise KerberosDependencyError(str(err))
        else:
            await set_state(self._session, KerberosState.READY)
            await self._session.commit()
            return await self._schedule_principal_task(request, user, data)

    async def _get_kdc_context(self) -> KDCContext:
        """Build and return context for KDC setup/config rendering.

        :raises Exception: If base DN cannot be retrieved.
        :return KDCContext: Typed dict with all required KDC context fields.
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
        data: KerberosSetupRequest,
    ) -> None:
        """Authenticate admin user for KDC setup.

        :param UserSchema user: User performing the setup.
        :param KerberosSetupRequest data: Setup request data.
        :raises KerberosDependencyError: If authentication fails.
        :return None: None.
        """
        if not await authenticate_user(
            self._session,
            user.user_principal_name,
            data.admin_password.get_secret_value(),
        ):
            raise KerberosDependencyError("Incorrect password")

    async def _schedule_principal_task(
        self,
        request: Request,
        user: UserSchema,
        data: KerberosSetupRequest,
    ) -> BackgroundTask:
        """Schedule background task for principal creation after KDC setup.

        :param Request request: FastAPI request (for DI container).
        :param UserSchema user: User for whom principal is created.
        :param KerberosSetupRequest data: Setup request data.
        :return BackgroundTask: Background task for principal creation.
        """
        async with request.app.state.dishka_container() as container:
            new_kadmin: AbstractKadmin = await container.get(AbstractKadmin)
            task = BackgroundTask(
                backoff.on_exception(
                    backoff.fibo,
                    Exception,
                    max_tries=10,
                    logger=None,
                    raise_on_giveup=False,
                )(new_kadmin.add_principal),
                user.user_principal_name.split("@")[0],
                data.admin_password.get_secret_value(),
            )
        return task

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
        except Exception as exc:
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
        self, principal_name: str, new_password: str
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
    ) -> tuple[AsyncIterator[bytes], BackgroundTask]:
        """Generate keytab and return (aiter_bytes, background_task).

        :param list[str] names: List of principal names.
        :raises KerberosNotFoundError: If principal not found.
        :return tuple: (aiter_bytes, background_task).
        """
        try:
            response = await self._kadmin.ktadd(names)
        except KRBAPIError:
            raise KerberosNotFoundError("Principal not found")
        return response.aiter_bytes(), BackgroundTask(response.aclose)

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
