"""RenameRequest for main router.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import AsyncContainer
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from application.ldap_requests import (
    ModifyDNRequest as LDAPModifyDNRequest,
    ModifyRequest as LDAPModifyRequest,
)
from application.ldap_responses import LDAPResult
from application.objects import Changes


class RenameRequest(BaseModel):
    """Rename Request. It's not RFC 4511.

    Combines ModifyDN and Modify operations.
    """

    object: str
    newrdn: str
    changes: list[Changes]

    @property
    def _new_object(self) -> str:
        return f"{self.newrdn},{','.join(self.object.split(',')[1:])}"

    @property
    def _oldrdn(self) -> str:
        return self.object.split(",")[0]

    async def _modify_dn_request(
        self,
        container: AsyncContainer,
        entry: str,
        newrdn: str,
    ) -> LDAPResult:
        modify_dn_request = LDAPModifyDNRequest(
            entry=entry,
            newrdn=newrdn,
            deleteoldrdn=True,
            new_superior=None,
        )
        return await modify_dn_request.handle_api(container)

    async def _expire_session_objects(self, container: AsyncContainer) -> None:
        session = await container.get(AsyncSession)
        session.expire_all()

    async def _modify_request(self, container: AsyncContainer) -> LDAPResult:
        modify_request = LDAPModifyRequest(
            object=self._new_object,
            changes=self.changes,
        )
        return await modify_request.handle_api(container)

    async def handle_api(self, container: AsyncContainer) -> LDAPResult:
        """Handle RenameRequest by executing ModifyDN then Modify.

        If ModifyRequest fails, rollback the ModifyDnRequest and return error.
        """
        modify_dn_response = await self._modify_dn_request(
            container,
            self.object,
            self.newrdn,
        )
        if not modify_dn_response or modify_dn_response.result_code != 0:
            return modify_dn_response

        await self._expire_session_objects(container)

        modify_response = await self._modify_request(container)
        if not modify_response or modify_response.result_code != 0:
            await self._modify_dn_request(
                container,
                self._new_object,
                self._oldrdn,
            )

        return modify_response
