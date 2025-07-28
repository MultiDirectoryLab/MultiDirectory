"""Extended request.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from typing import AsyncGenerator, ClassVar

from asn1 import Decoder
from loguru import logger
from pydantic import BaseModel, SecretStr, SerializeAsAny
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.asn1parser import LDAPOID, ASN1Row, asn1todict
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import (
    BaseExtendedResponseValue,
    ExtendedResponse,
)
from ldap_protocol.objects import ProtocolRequests
from ldap_protocol.policies.password_policy import (
    PasswordPolicySchema,
    post_save_password_actions,
)
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.utils.queries import get_user
from models import Directory, User
from security import get_password_hash, verify_password

from .base import BaseRequest


class BaseExtendedValue(ABC, BaseModel):
    """Base extended request body."""

    REQUEST_ID: ClassVar[LDAPOID]

    def __init_subclass__(cls, **kwargs: dict) -> None:
        """Check if OID is valid."""
        super().__init_subclass__(**kwargs)  # type: ignore

        if not LDAPOID.has_value(cls.REQUEST_ID):
            raise ValueError(f"Invalid OID: {cls.REQUEST_ID}")

    @classmethod
    @abstractmethod
    def from_data(cls, data: ASN1Row) -> "BaseExtendedValue":
        """Create model from data, decoded from responseValue bytes."""

    @abstractmethod
    async def handle(
        self,
        ldap_session: LDAPSession,
        session: AsyncSession,
        kadmin: AbstractKadmin,
        settings: Settings,
        role_use_case: RoleUseCase,
    ) -> BaseExtendedResponseValue:
        """Generate specific extended resoponse."""

    @staticmethod
    def _decode_value(data: ASN1Row) -> ASN1Row:
        dec = Decoder()
        dec.start(data[1].value)  # type: ignore
        output = asn1todict(dec)
        return output[0].value


class WhoAmIResponse(BaseExtendedResponseValue):
    """WhoAmI response.

    RFC 4513;

    authzId = dnAuthzId / uAuthzId

    ; distinguished-name-based authz id
    dnAuthzId =  "dn:" distinguishedName

    ; unspecified authorization id, UTF-8 encoded
    uAuthzId = "u:" userid
    userid = *UTF8 ; syntax unspecified
    """

    authz_id: str

    def get_value(self) -> str | None:
        """Get authz id."""
        return self.authz_id


class WhoAmIRequestValue(BaseExtendedValue):
    """LDAP who am i request.

    RFC 4532;
    """

    REQUEST_ID: ClassVar[LDAPOID] = LDAPOID.WHOAMI
    base: int = 123

    @classmethod
    def from_data(cls, data: ASN1Row) -> "WhoAmIRequestValue":  # noqa: ARG003
        """Create model from data, WhoAmIRequestValue data is empty."""
        return cls()

    async def handle(
        self,
        ldap_session: LDAPSession,
        _: AsyncSession,
        kadmin: AbstractKadmin,  # noqa: ARG002
        settings: Settings,  # noqa: ARG002
        role_use_case: RoleUseCase,  # noqa: ARG002
    ) -> "WhoAmIResponse":
        """Return user from session."""
        un = (
            f"u:{ldap_session.user.user_principal_name}"
            if ldap_session.user
            else ""
        )

        return WhoAmIResponse(authz_id=un)


class StartTLSResponse(BaseExtendedResponseValue):
    """Start tls response."""

    def get_value(self) -> str | None:
        """Get response value."""
        return ""


class StartTLSRequestValue(BaseExtendedValue):
    """Start tls request."""

    REQUEST_ID: ClassVar[LDAPOID] = LDAPOID.START_TLS

    async def handle(
        self,
        ldap_session: LDAPSession,  # noqa: ARG002
        session: AsyncSession,  # noqa: ARG002
        kadmin: AbstractKadmin,  # noqa: ARG002
        settings: Settings,
        role_use_case: RoleUseCase,  # noqa: ARG002
    ) -> StartTLSResponse:
        """Update password of current or selected user."""
        if settings.USE_CORE_TLS:
            return StartTLSResponse()

        raise PermissionError("No TLS")

    @classmethod
    def from_data(cls, data: ASN1Row) -> "StartTLSRequestValue":  # noqa: ARG003
        """Create model from data, decoded from responseValue bytes."""
        return cls()


class PasswdModifyResponse(BaseExtendedResponseValue):
    """Password modify response.

    PasswdModifyResponseValue ::= SEQUENCE {
        genPasswd       [0]     OCTET STRING OPTIONAL }
    """

    gen_passwd: str = ""

    def get_value(self) -> str | None:
        """Return gen password."""
        return self.gen_passwd


class PasswdModifyRequestValue(BaseExtendedValue):
    """Described in RFC3062.

    The Password Modify operation is an LDAPv3 Extended Operation
    [RFC2251, Section 4.12] and is identified by the OBJECT IDENTIFIER
    passwdModifyOID.  This section details the syntax of the protocol
    request and response.

    passwdModifyOID OBJECT IDENTIFIER ::= 1.3.6.1.4.1.4203.1.11.1

    PasswdModifyRequestValue ::= SEQUENCE {
        userIdentity    [0]  OCTET STRING OPTIONAL
        oldPasswd       [1]  OCTET STRING OPTIONAL
        newPasswd       [2]  OCTET STRING OPTIONAL }
    """

    REQUEST_ID: ClassVar[LDAPOID] = LDAPOID.PASSWORD_MODIFY
    user_identity: str | None = None
    old_password: SecretStr
    new_password: SecretStr

    async def handle(
        self,
        ldap_session: LDAPSession,
        session: AsyncSession,
        kadmin: AbstractKadmin,
        settings: Settings,
        role_use_case: RoleUseCase,
    ) -> PasswdModifyResponse:
        """Update password of current or selected user."""
        if not settings.USE_CORE_TLS:
            raise PermissionError("TLS required")

        user: User
        old_password = self.old_password.get_secret_value()
        new_password = self.new_password.get_secret_value()

        if self.user_identity is not None:
            user = await get_user(session, self.user_identity)  # type: ignore
            if user is None:
                raise PermissionError("Cannot acquire user by DN")
        else:
            if not ldap_session.user:
                raise PermissionError("Anonymous user")

            user = await session.get(User, ldap_session.user.id)  # type: ignore

        validator = await PasswordPolicySchema.get_policy_settings(session)

        errors = await validator.validate_password_with_policy(
            password=new_password,
            user=user,
        )

        p_last_set = await validator.get_pwd_last_set(
            session,
            user.directory_id,
        )

        if validator.validate_min_age(p_last_set):
            errors.append("Minimum age violation")

        if ldap_session.user and self.user_identity:
            pwd_ace = await role_use_case.get_password_ace(
                dir_id=user.directory_id,
                user_role_ids=ldap_session.user.role_ids,
            )

            if not pwd_ace:
                if not await role_use_case.contains_domain_admins_role(
                    ldap_session.user.role_ids
                ):
                    raise PermissionError("No password modify access")
            elif not pwd_ace.is_allow:
                raise PermissionError("No password modify access")

        if not errors and (
            user.password is None
            or verify_password(old_password, user.password)
        ):
            try:
                await kadmin.create_or_update_principal_pw(
                    user.get_upn_prefix(),
                    new_password,
                )
            except KRBAPIError:
                await session.rollback()
                raise PermissionError("Kadmin Error")

            user.password = get_password_hash(new_password)
            await post_save_password_actions(user, session)
            await session.execute(
                update(Directory).where(Directory.id == user.directory_id),
            )
            await session.commit()

            return PasswdModifyResponse()
        raise PermissionError("No user provided")

    @classmethod
    def from_data(cls, data: ASN1Row) -> "PasswdModifyRequestValue":
        """Create model from data, decoded from responseValue bytes."""
        d: list = cls._decode_value(data)  # type: ignore
        if len(d) == 3:
            return cls(
                user_identity=d[0].value,
                old_password=d[1].value,
                new_password=d[2].value,
            )

        return cls(old_password=d[0].value, new_password=d[1].value)


_REQUEST_LIST: list[type[BaseExtendedValue]] = [
    PasswdModifyRequestValue,
    WhoAmIRequestValue,
    StartTLSRequestValue,
]


EXTENDED_REQUEST_OID_MAP: dict[LDAPOID, type[BaseExtendedValue]] = {
    req.REQUEST_ID: req for req in _REQUEST_LIST
}


class ExtendedRequest(BaseRequest):
    """Extended protocol.

    ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
        requestName      [0] LDAPOID,
        requestValue     [1] OCTET STRING OPTIONAL }
    """

    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.EXTENDED
    request_name: LDAPOID
    request_value: SerializeAsAny[BaseExtendedValue]

    async def handle(
        self,
        ldap_session: LDAPSession,
        session: AsyncSession,
        kadmin: AbstractKadmin,
        settings: Settings,
        role_use_case: RoleUseCase,
    ) -> AsyncGenerator[ExtendedResponse, None]:
        """Call proxy handler."""
        try:
            response = await self.request_value.handle(
                ldap_session,
                session,
                kadmin,
                settings,
                role_use_case,
            )
        except PermissionError as err:
            logger.critical(err)
            yield ExtendedResponse(
                result_code=LDAPCodes.OPERATIONS_ERROR,
                response_name=self.request_name,
                response_value=None,
            )
        else:
            yield ExtendedResponse(
                result_code=LDAPCodes.SUCCESS,
                response_name=self.request_name,
                response_value=response,
            )

    @classmethod
    def from_data(cls, data: list[ASN1Row]) -> "ExtendedRequest":
        """Create extended request from asn.1 decoded string.

        :param ASN1Row data: any data
        :return ExtendedRequest: universal request
        """
        oid = data[0].value
        ext_request = EXTENDED_REQUEST_OID_MAP[oid]
        return cls(
            request_name=oid,
            request_value=ext_request.from_data(data),  # type: ignore
        )
