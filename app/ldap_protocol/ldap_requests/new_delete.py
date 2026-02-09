"""Delete protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from domain.directory.deletion_exception import (
    DomainDirectoryDeletionError,
    SystemDirectoryDeletionError,
    UserSelfDeletionError,
)

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.kerberos.exceptions import (
    KRBAPIConnectionError,
    KRBAPIDeletePrincipalError,
    KRBAPIPrincipalNotFoundError,
)
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    DeleteResponse,
)
from ldap_protocol.objects import ProtocolRequests
from ldap_protocol.utils.queries import validate_entry

from .base import BaseRequest
from .contexts import LDAPDeleteRequestContext, LDAPNewDeleteRequestContext

DELETE_EXCEPTION_STACK = (
    SystemDirectoryDeletionError,
    DomainDirectoryDeletionError,
    UserSelfDeletionError,
)


class NewDeleteRequest(BaseRequest):
    """Delete request.

    DelRequest ::= [APPLICATION 10] LDAPDN
    """

    RESPONSE_TYPE: ClassVar[type] = DeleteResponse
    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.DELETE
    CONTEXT_TYPE: ClassVar[type] = LDAPDeleteRequestContext

    entry: str

    @classmethod
    def from_data(cls, data: ASN1Row) -> "NewDeleteRequest":
        return cls(entry=data)

    @staticmethod
    def _match_bad_response(err: BaseException) -> tuple[LDAPCodes, str]:
        match err:
            case SystemDirectoryDeletionError():
                return LDAPCodes.UNWILLING_TO_PERFORM, ""

            case DomainDirectoryDeletionError():
                return LDAPCodes.UNWILLING_TO_PERFORM, ""

            case UserSelfDeletionError():
                return LDAPCodes.OPERATIONS_ERROR, "Cannot delete yourself."

            case KRBAPIDeletePrincipalError():
                return LDAPCodes.UNAVAILABLE, "KerberosError"

            case KRBAPIConnectionError():
                return LDAPCodes.UNAVAILABLE, "KerberosError"

            case PermissionError():
                return LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS, ""

            case _:
                raise err

    async def handle(
        self,
        ctx: LDAPNewDeleteRequestContext,
    ) -> AsyncGenerator[DeleteResponse, None]:
        """Delete request handler."""
        if ctx.ldap_session.is_anonymous:
            yield DeleteResponse(**INVALID_ACCESS_RESPONSE)
            return

        if not validate_entry(self.entry.lower()):
            yield DeleteResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        try:
            await ctx.delete_directory_use_case.execute(
                entry=self.entry,
                user=ctx.ldap_session.user,
            )
        except KRBAPIPrincipalNotFoundError:
            pass
        except DELETE_EXCEPTION_STACK as err:
            result_code, error_message = self._match_bad_response(err)
            yield DeleteResponse(
                result_code=result_code,
                error_message=error_message,
            )
            return

        yield DeleteResponse(result_code=LDAPCodes.SUCCESS)
