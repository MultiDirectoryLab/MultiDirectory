"""FastAPI adapter for KerberosService."""

from typing import Any, AsyncGenerator, Awaitable, Callable, ParamSpec, TypeVar

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import SecretStr
from starlette.background import BackgroundTask

from api.main.schema import KerberosSetupRequest
from ldap_protocol.dialogue import LDAPSession, UserSchema
from ldap_protocol.kerberos import KerberosState
from ldap_protocol.kerberos.exceptions import (
    KerberosBaseDnNotFoundError,
    KerberosConflictError,
    KerberosDependencyError,
    KerberosNotFoundError,
    KerberosUnavailableError,
)
from ldap_protocol.kerberos.service import KerberosService
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO

P = ParamSpec("P")
R = TypeVar("R")


class KerberosFastAPIAdapter:
    """Adapter for using KerberosService with FastAPI and background tasks."""

    def __init__(self, service: "KerberosService"):
        """Initialize the adapter with a KerberosService instance.

        :param service: KerberosService instance (domain logic)
        """
        self._service = service

    async def _sc(
        self,
        func: Callable[P, Awaitable[R]],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        """Convert Kerberos exceptions to HTTPException.

        :raises HTTPException: on Kerberos errors
        :return: Result of the function call.
        """
        try:
            return await func(*args, **kwargs)
        except KerberosDependencyError as exc:
            raise HTTPException(
                status.HTTP_424_FAILED_DEPENDENCY, detail=str(exc)
            )
        except KerberosNotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
        except KerberosConflictError:
            raise HTTPException(status.HTTP_409_CONFLICT)
        except KerberosUnavailableError:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE)
        except KerberosBaseDnNotFoundError as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
            )

    async def setup_krb_catalogue(
        self,
        mail: str,
        krbadmin_password: SecretStr,
        ldap_session: LDAPSession,
        entity_type_dao: EntityTypeDAO,
    ) -> None:
        """Create Kerberos structure in the LDAP directory.

        :raises HTTPException: on Kerberos errors
        :return: None
        """
        return await self._sc(
            self._service.setup_krb_catalogue,
            mail,
            krbadmin_password,
            ldap_session,
            entity_type_dao,
        )

    async def setup_kdc(
        self,
        data: KerberosSetupRequest,
        user: UserSchema,
        request: Request,
    ) -> Response:
        """Set up KDC, generate configs, and schedule background task.

        :raises HTTPException: on Kerberos errors
        :return: BackgroundTask (background task scheduled)
        """
        task_struct = await self._sc(
            self._service.setup_kdc,
            data.krbadmin_password.get_secret_value(),
            data.admin_password.get_secret_value(),
            data.stash_password.get_secret_value(),
            user,
            request,
        )
        task = BackgroundTask(
            task_struct.func,
            *task_struct.args,
            **task_struct.kwargs,
        )
        return Response(background=task)

    async def add_principal(
        self,
        primary: str,
        instance: str,
    ) -> None:
        """Create principal in Kerberos with given name.

        :raises HTTPException: on Kerberos errors
        :return: None
        """
        return await self._sc(self._service.add_principal, primary, instance)

    async def rename_principal(
        self,
        principal_name: str,
        principal_new_name: str,
    ) -> None:
        """Rename principal in Kerberos.

        :raises HTTPException: on Kerberos errors
        :return: None
        """
        return await self._sc(
            self._service.rename_principal,
            principal_name,
            principal_new_name,
        )

    async def reset_principal_pw(
        self,
        principal_name: str,
        new_password: str,
    ) -> None:
        """Reset principal password in Kerberos.

        :raises HTTPException: on Kerberos errors
        :return: None
        """
        return await self._sc(
            self._service.reset_principal_pw,
            principal_name,
            new_password,
        )

    async def delete_principal(
        self,
        principal_name: str,
    ) -> None:
        """Delete principal in Kerberos.

        :raises HTTPException: on Kerberos errors
        :return: None
        """
        return await self._sc(self._service.delete_principal, principal_name)

    async def ktadd(
        self,
        names: list[str],
    ) -> StreamingResponse:
        """Generate keytab and return as streaming response.

        :raises HTTPException: on Kerberos errors
        :return: StreamingResponse
        """
        aiter_bytes, task_struct = await self._sc(
            self._service.ktadd,
            names,
        )
        task = BackgroundTask(
            task_struct.func,
            *task_struct.args,
            **task_struct.kwargs,
        )
        if isinstance(aiter_bytes, bytes):

            async def _bytes_to_async_iter(
                data: bytes,
            ) -> AsyncGenerator[bytes, Any]:
                yield data

            aiter_bytes = _bytes_to_async_iter(aiter_bytes)

        return StreamingResponse(
            aiter_bytes,
            media_type="application/txt",
            headers={
                "Content-Disposition": 'attachment; filename="krb5.keytab"'
            },
            background=task,
        )

    async def get_status(self) -> KerberosState:
        """Get Kerberos server state.

        :raises HTTPException: on Kerberos errors
        :return: KerberosState
        """
        return await self._sc(self._service.get_status)
