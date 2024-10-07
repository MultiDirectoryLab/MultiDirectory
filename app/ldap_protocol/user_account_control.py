"""userAccountControl attribute handling.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntFlag
from typing import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Attribute


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
        """
        Check all flags set in the userAccountControl value.

        :param int uac_value: userAccountControl attribute value
        :return: True if the value is valid (only known flags), False otherwise
        """
        if isinstance(uac_value, int):
            pass
        elif isinstance(uac_value, str) and uac_value.isdigit():
            uac_value = int(uac_value)
        else:
            return False

        return False if uac_value & ~sum(flag.value for flag in cls) else True


async def get_check_uac(
    session: AsyncSession,
    directory_id: int,
) -> Callable[[UserAccountControlFlag], bool]:
    """Get userAccountControl attribute and check binary flags in it.

    :param AsyncSession session: SA async session
    :param int directory_id: id
    :return Callable: function to check given flag in current
        userAccountControl attribute
    """
    query = (
        select(Attribute)
        .filter_by(directory_id=directory_id, name="userAccountControl")
    )
    uac = await session.scalar(query)

    value = uac.value if uac is not None else "0"

    def is_flag_true(flag: UserAccountControlFlag) -> bool:
        """Check given flag in current userAccountControl attribute.

        :param userAccountControlFlag flag: flag
        :return bool: result
        """
        return bool(int(value) & flag)

    return is_flag_true
