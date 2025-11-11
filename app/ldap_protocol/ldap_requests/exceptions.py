"""Exceptions for LDAP requests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class ModifyError(Exception):
    """Modify error."""


class PasswordModifyError(ModifyError):
    """Password modify error."""


class PasswordModifyUserNotFoundError(PasswordModifyError):
    """Password modify user not found error."""


class PasswordModifyUserNotAllowedError(PasswordModifyError):
    """Password modify user not allowed error."""


class PasswordModifyPasswordChangeRestrictedError(PasswordModifyError):
    """Password modify password change restricted error."""


class PasswordModifyNoPasswordModifyAccessError(PasswordModifyError):
    """Password modify no password modify access error."""


class PasswordModifyKadminError(PasswordModifyError):
    """Password modify kadmin error."""


class PasswordModifyNoUserProvidedError(PasswordModifyError):
    """Password modify no user provided error."""
