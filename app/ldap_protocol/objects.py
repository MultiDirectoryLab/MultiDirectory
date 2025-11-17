"""Subcontainers for requests/responses.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, IntFlag, StrEnum, unique
from typing import Annotated

import annotated_types
from pydantic import BaseModel, field_validator


class Scope(IntEnum):
    """Enum for search request."""

    BASE_OBJECT = 0
    SINGLE_LEVEL = 1
    WHOLE_SUBTREE = 2
    SUBORDINATE_SUBTREE = 3


class DerefAliases(IntEnum):
    """Enum for search request."""

    NEVER_DEREF_ALIASES = 0
    DEREF_IN_SEARCHING = 1
    DEREF_FINDING_BASE_OBJ = 2
    DEREF_ALWAYS = 3


class LDAPMatchingRule(StrEnum):
    """Enum for LDAP Matching Rules (extensibleMatch)."""

    LDAP_MATCHING_RULE_BIT_AND = "1.2.840.113556.1.4.803"
    LDAP_MATCHING_RULE_BIT_OR = "1.2.840.113556.1.4.804"
    LDAP_MATCHING_RULE_TRANSITIVE_EVAL = "1.2.840.113556.1.4.1941"
    LDAP_MATCHING_RULE_DN_WITH_DATA = "1.2.840.113556.1.4.2253"


class Operation(IntEnum):
    """Changes enum for modify request."""

    ADD = 0
    DELETE = 1
    REPLACE = 2


class PartialAttribute(BaseModel):
    """Partial attribite structure. Description in rfc2251 4.1.6."""

    type: Annotated[str, annotated_types.Len(max_length=8100)]
    vals: list[Annotated[str | bytes, annotated_types.Len(max_length=100000)]]

    @property
    def l_name(self) -> str:
        """Get lower case name."""
        return self.type.lower()

    @field_validator("type", mode="before")
    @classmethod
    def validate_type(cls, v: str | bytes | int) -> str:
        return str(v)

    @field_validator("vals", mode="before")
    @classmethod
    def validate_vals(cls, vals: list[str | int | bytes]) -> list[str | bytes]:
        return [v if isinstance(v, bytes) else str(v) for v in vals]

    class Config:
        """Allow class to use property."""

        arbitrary_types_allowed = True
        json_encoders = {
            bytes: lambda value: value.hex(),
        }


class Changes(BaseModel):
    """Changes for modify request."""

    operation: Operation
    modification: PartialAttribute

    def get_name(self) -> str:
        """Get mod name."""
        return self.modification.type.lower()


@unique
class ProtocolRequests(IntEnum):
    """Enum for LDAP requests."""

    BIND = 0
    UNBIND = 2
    SEARCH = 3
    MODIFY = 6
    ADD = 8
    DELETE = 10
    MODIFY_DN = 12
    COMPARE = 14
    ABANDON = 16
    EXTENDED = 23


@unique
class ProtocolResponse(IntEnum):
    """Enum for LDAP resposnes."""

    BIND = 1
    SEARCH_RESULT_ENTRY = 4
    SEARCH_RESULT_DONE = 5
    MODIFY = 7
    ADD = 9
    DELETE = 11
    MODIFY_DN = 13
    COMPARE = 15
    EXTENDED = 24
    INTERMEDIATE = 25
    SEARCH_RESULT_REFERENCE = 19


@unique
class OperationEvent(IntEnum):
    """Enum for operation events. Includes all LDAP requests."""

    BIND = ProtocolRequests.BIND
    UNBIND = ProtocolRequests.UNBIND
    SEARCH = ProtocolRequests.SEARCH
    MODIFY = ProtocolRequests.MODIFY
    ADD = ProtocolRequests.ADD
    DELETE = ProtocolRequests.DELETE
    MODIFY_DN = ProtocolRequests.MODIFY_DN
    COMPARE = ProtocolRequests.COMPARE
    ABANDON = ProtocolRequests.ABANDON
    EXTENDED = ProtocolRequests.EXTENDED
    CHANGE_PASSWORD = 40
    AFTER_2FA = 41
    KERBEROS_AUTH = 42
    CHANGE_PASSWORD_KERBEROS = 43


class UserAccountControlFlag(IntFlag):
    """userAccountControl flags mapping.

    SCRIPT (0x0001): The logon script will be executed.
    ACCOUNTDISABLE (0x0002): The account is disabled.
    HOMEDIR_REQUIRED (0x0008): The home directory is required.
    LOCKOUT (0x0010): The account is currently locked out.
    PASSWD_NOTREQD (0x0020): No password is required for the account.
    PASSWD_CANT_CHANGE (0x0040): The user cannot change the password.
    ENCRYPTED_TEXT_PWD_ALLOWED (0x0080): Encrypted plaintext password
                                         is allowed.
    TEMP_DUPLICATE_ACCOUNT (0x0100): A temporary duplicate account,
                                     often for a user object.
    NORMAL_ACCOUNT (0x0200): A typical user account (default).
    INTERDOMAIN_TRUST_ACCOUNT (0x0800): An account for interdomain trusts.
    WORKSTATION_TRUST_ACCOUNT (0x1000): A workstation trust account.
    SERVER_TRUST_ACCOUNT (0x2000): A server trust account.
    DONT_EXPIRE_PASSWORD (0x10000): The password never expires.
    MNS_LOGON_ACCOUNT (0x20000): MNS logon account (Microsoft Network Server).
    SMARTCARD_REQUIRED (0x40000): Logon requires a smart card.
    TRUSTED_FOR_DELEGATION (0x80000): The account is trusted for delegation.
    NOT_DELEGATED (0x100000): The account is not trusted for delegation.
    USE_DES_KEY_ONLY (0x200000): Only DES encryption is allowed for the account
    DONT_REQUIRE_PREAUTH (0x400000): The account does not require
                                     Kerberos pre-authentication.
    PASSWORD_EXPIRED (0x800000): The password for the account has expired.
    TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000): The account is trusted to
                                                authenticate for delegation.
    PARTIAL_SECRETS_ACCOUNT (0x04000000): A read-only domain controller account
                                          (partial secrets).
    """

    SCRIPT = 0x0001
    ACCOUNTDISABLE = 0x0002
    HOMEDIR_REQUIRED = 0x0008
    LOCKOUT = 0x0010
    PASSWD_NOTREQD = 0x0020
    PASSWD_CANT_CHANGE = 0x0040
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
    TEMP_DUPLICATE_ACCOUNT = 0x0100
    NORMAL_ACCOUNT = 0x0200
    INTERDOMAIN_TRUST_ACCOUNT = 0x0800
    WORKSTATION_TRUST_ACCOUNT = 0x1000
    SERVER_TRUST_ACCOUNT = 0x2000
    DONT_EXPIRE_PASSWORD = 0x10000
    MNS_LOGON_ACCOUNT = 0x20000
    SMARTCARD_REQUIRED = 0x40000
    TRUSTED_FOR_DELEGATION = 0x80000
    NOT_DELEGATED = 0x100000
    USE_DES_KEY_ONLY = 0x200000
    DONT_REQUIRE_PREAUTH = 0x400000
    PASSWORD_EXPIRED = 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    PARTIAL_SECRETS_ACCOUNT = 0x04000000

    @classmethod
    def is_value_valid(cls, uac_value: str | int) -> bool:
        """Check all flags set in the userAccountControl value.

        :param int uac_value: userAccountControl attribute value
        :return: True if the value is valid (only known flags), False otherwise
        """
        if isinstance(uac_value, int):
            pass
        elif isinstance(uac_value, str) and uac_value.isdigit():
            uac_value = int(uac_value)
        else:
            return False

        if uac_value == 0:
            return False

        return not uac_value & ~sum(flag.value for flag in cls)
