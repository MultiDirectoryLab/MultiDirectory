"""FastAPI adapter for KerberosService.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Any, AsyncGenerator

from fastapi import Request, Response
from fastapi.responses import StreamingResponse
from pydantic import SecretStr
from starlette.background import BackgroundTask

from api.base_adapter import BaseAdapter
from api.main.schema import KerberosSetupRequest, KtaddRequest, ModifyPrincipalRequest, PrincipalAddRequest
from ldap_protocol.dialogue import LDAPSession, UserSchema
from ldap_protocol.kerberos import KerberosState
from ldap_protocol.kerberos.service import KerberosService
from ldap_protocol.ldap_requests.contexts import LDAPAddRequestContext


class KerberosFastAPIAdapter(BaseAdapter[KerberosService]):
    """Adapter for using KerberosService with FastAPI and background tasks."""

    async def setup_krb_catalogue(
        self, mail: str, krbadmin_password: SecretStr, ldap_session: LDAPSession, ctx: LDAPAddRequestContext
    ) -> None:
        """Create Kerberos structure in the LDAP directory.

        :raises HTTPException: on Kerberos errors
        :return: None
        """
        return await self._service.setup_krb_catalogue(mail, krbadmin_password, ldap_session, ctx)

    async def setup_kdc(self, data: KerberosSetupRequest, user: UserSchema, request: Request) -> Response:
        """Set up KDC, generate configs, and schedule background task.

        :raises HTTPException: on Kerberos errors
        :return: BackgroundTask (background task scheduled)
        """
        task_struct = await self._service.setup_kdc(
            data.krbadmin_password.get_secret_value(),
            data.admin_password.get_secret_value(),
            data.stash_password.get_secret_value(),
            user,
            request,
        )
        task = BackgroundTask(task_struct.func, *task_struct.args, **task_struct.kwargs)
        return Response(background=task)

    async def add_principal(self, request: PrincipalAddRequest) -> None:
        """Create principal in Kerberos with given name.

        :raises HTTPException: on Kerberos errors
        :return: None
        """
        return await self._service.add_principal(
            request.principal_name, password=request.password, algorithms=request.algorithms
        )

    async def modify_principal(self, request: ModifyPrincipalRequest) -> None:
        """Modify principal ( password, algorithms).

        :raises HTTPException: on Kerberos errors
        :return: None
        """
        return await self._service.modify_principal(
            principal_name=request.principal_name,
            new_name=request.new_name,
            algorithms=request.algorithms,
            password=request.password,
        )

    async def delete_principal(self, principal_name: str) -> None:
        """Delete principal in Kerberos.

        :raises HTTPException: on Kerberos errors
        :return: None
        """
        return await self._service.delete_principal(principal_name)

    async def ktadd(self, data: KtaddRequest) -> StreamingResponse:
        """Generate keytab and return as streaming response.

        :raises HTTPException: on Kerberos errors
        :return: StreamingResponse
        """
        aiter_bytes, task_struct = await self._service.ktadd(data.names, is_rand_key=data.is_rand_key)
        task = BackgroundTask(task_struct.func, *task_struct.args, **task_struct.kwargs)
        if isinstance(aiter_bytes, bytes):

            async def _bytes_to_async_iter(data: bytes) -> AsyncGenerator[bytes, Any]:
                yield data

            aiter_bytes = _bytes_to_async_iter(aiter_bytes)

        return StreamingResponse(
            aiter_bytes,
            media_type="application/txt",
            headers={"Content-Disposition": 'attachment; filename="krb5.keytab"'},
            background=task,
        )

    async def get_status(self) -> KerberosState:
        """Get Kerberos server state.

        :raises HTTPException: on Kerberos errors
        :return: KerberosState
        """
        return await self._service.get_status()
