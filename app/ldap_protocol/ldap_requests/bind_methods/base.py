"""LDAP bind auth methods structure.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import ClassVar

from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import BindResponse
from models import User


class SASLMethod(StrEnum):
    """SASL choices."""

    PLAIN = "PLAIN"
    EXTERNAL = "EXTERNAL"
    GSSAPI = "GSSAPI"
    CRAM_MD5 = "CRAM-MD5"
    DIGEST_MD5 = "DIGEST-MD5"
    SCRAM_SHA_1 = "SCRAM-SHA-1"
    SCRAM_SHA_256 = "SCRAM-SHA-256"
    OAUTHBEARER = "OAUTHBEARER"
    UNBOUNDID_CERTIFICATE_PLUS_PASSWORD = "UNBOUNDID-CERTIFICATE-PLUS-PASSWORD"  # noqa
    UNBOUNDID_TOTP = "UNBOUNDID-TOTP"
    UNBOUNDID_DELIVERED_OTP = "UNBOUNDID-DELIVERED-OTP"
    UNBOUNDID_YUBIKEY_OTP = "UNBOUNDID-YUBIKEY-OTP"


class LDAPBindErrors(StrEnum):
    """LDAP Bind errors."""

    NO_SUCH_USER = "525"
    LOGON_FAILURE = "52e"
    INVALID_LOGON_HOURS = "530"
    INVALID_WORKSTATION = "531"
    PASSWORD_EXPIRED = "532"  # noqa
    ACCOUNT_DISABLED = "533"
    ACCOUNT_EXPIRED = "701"
    PASSWORD_MUST_CHANGE = "773"  # noqa
    ACCOUNT_LOCKED_OUT = "775"

    def __str__(self) -> str:
        """Return the error message as a string.

        Returns:
            str: Error message
        """
        return (
            "80090308: LdapErr: DSID-0C09030B, "
            "comment: AcceptSecurityContext error, "
            f"data {self.value}, v893"
        )


def get_bad_response(error_message: LDAPBindErrors) -> BindResponse:
    """Generate BindResponse object with an invalid credentials error.

    Args:
        error_message (LDAPBindErrors): Error message to include in the\
            response

    Returns:
        BindResponse: A response object with the result code set to\
            INVALID_CREDENTIALS, an empty matchedDN, and the provided error\
            message
    """
    return BindResponse(
        result_code=LDAPCodes.INVALID_CREDENTIALS,
        matchedDN="",
        errorMessage=str(error_message),
    )


class AbstractLDAPAuth(ABC, BaseModel):
    """Auth base class."""

    otpassword: str | None = Field(None, max_length=6, min_length=6)
    password: SecretStr

    @property
    @abstractmethod
    def METHOD_ID(self) -> int:  # noqa: N802
        """Abstract method id."""

    @abstractmethod
    def is_valid(self, user: User) -> bool:
        """Validate state.

        Args:
            user (User): instance of User.

        Returns:
            bool:
        """

    @abstractmethod
    def is_anonymous(self) -> bool:
        """Check if anonymous.

        Returns:
            bool: True if anonymous, False otherwise
        """

    @abstractmethod
    async def get_user(self, session: AsyncSession, username: str) -> User:
        """Get user.

        Args:
            session (AsyncSession): async db session.
            username (str): user name.

        Returns:
            User: instance of User.
        """


class SaslAuthentication(AbstractLDAPAuth):
    """Sasl auth form."""

    METHOD_ID: ClassVar[int] = 3
    mechanism: ClassVar[SASLMethod]

    @classmethod
    @abstractmethod
    def from_data(cls, data: list[ASN1Row]) -> "SaslAuthentication":
        """Get auth from data.

        Args:
            data (list[ASN1Row]): list of row with metadata.

        Returns:
            SaslAuthentication: Sasl auth form.
        """
