"""FastAPI adapter for KerberosService."""

from fastapi import HTTPException, Request, status
from pydantic import SecretStr
from starlette.background import BackgroundTask

from api.exceptions import (
    KerberosDependencyError,
    KerberosNotFoundError,
    KerberosUnavailableError,
)
from api.main.schema import KerberosSetupRequest
from ldap_protocol.dialogue import LDAPSession, UserSchema
from ldap_protocol.kerberos_service import KerberosService
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO


class KerberosFastAPIAdapter:
    """Adapter for using KerberosService with FastAPI and background tasks."""

    def __init__(self, service: "KerberosService"):
        """Initialize the adapter with a KerberosService instance.

        :param service: KerberosService instance (domain logic)
        """
        self._service = service

    async def setup_krb_catalogue(
        self,
        mail: str,
        krbadmin_password: SecretStr,
        ldap_session: LDAPSession,
        entity_type_dao: EntityTypeDAO,
    ) -> None:
        """Create Kerberos structure in the LDAP directory.

        :raises HTTPException: 409 if structure creation conflict
        :return: None
        """
        try:
            await self._service.setup_krb_catalogue(
                mail,
                krbadmin_password,
                ldap_session,
                entity_type_dao,
            )
        except KerberosDependencyError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc))

    async def setup_kdc(
        self,
        data: KerberosSetupRequest,
        user: UserSchema,
        request: Request,
    ) -> BackgroundTask:
        """Set up KDC, generate configs, and schedule background task.

        :raises HTTPException: 500 if dependency/auth error
        :return: BackgroundTask (background task scheduled)
        """
        try:
            func, args, kwargs = await self._service.setup_kdc(
                data,
                user,
                request,
            )
            return BackgroundTask(func, *args, **kwargs)
        except KerberosDependencyError as exc:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(exc),
            )

    async def add_principal(
        self,
        primary: str,
        instance: str,
    ) -> None:
        """Create principal in Kerberos with given name.

        :raises HTTPException: 424 if kadmin request failed
        :return: None
        """
        await self._service.add_principal(primary, instance)

    async def rename_principal(
        self,
        principal_name: str,
        principal_new_name: str,
    ) -> None:
        """Rename principal in Kerberos.

        :raises HTTPException: 424 if kadmin request failed
        :return: None
        """
        await self._service.rename_principal(
            principal_name,
            principal_new_name,
        )

    async def reset_principal_pw(
        self,
        principal_name: str,
        new_password: str,
    ) -> None:
        """Reset principal password in Kerberos.

        :raises HTTPException: 424 if kadmin request failed
        :return: None
        """
        await self._service.reset_principal_pw(principal_name, new_password)

    async def delete_principal(
        self,
        principal_name: str,
    ) -> None:
        """Delete principal in Kerberos.

        :raises HTTPException: 424 if kadmin request failed
        :return: None
        """
        await self._service.delete_principal(principal_name)

    async def ktadd(
        self,
        names: list[str],
    ) -> tuple[bytes, BackgroundTask]:
        """Generate keytab and return as streaming response.

        :raises HTTPException: 404 if principal not found
        :return: StreamingResponse
        """
        try:
            aiter_bytes, (func, args, kwargs) = await self._service.ktadd(
                names
            )
            return aiter_bytes, BackgroundTask(func, *args, **kwargs)

        except KerberosNotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc))

    async def get_status(self) -> str:
        """Get Kerberos server state.

        :raises HTTPException: 503 if server unavailable
        :return: str (KerberosState)
        """
        try:
            state = await self._service.get_status()
            return state.value
        except KerberosUnavailableError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
