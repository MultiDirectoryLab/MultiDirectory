"""Exception package for authentication and MFA related errors.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .auth import (
    AlreadyConfiguredError,
    ForbiddenError,
    LoginFailedError,
    PasswordPolicyError,
    UnauthorizedError,
    UserNotFoundError,
)
from .mfa import (
    AuthenticationError,
    InvalidCredentialsError,
    MFARequiredError,
    MFATokenError,
    MissingMFACredentialsError,
    NetworkPolicyError,
    NotFoundError,
)

__all__ = [
    "UnauthorizedError",
    "AlreadyConfiguredError",
    "ForbiddenError",
    "LoginFailedError",
    "PasswordPolicyError",
    "UserNotFoundError",
    "MFARequiredError",
    "MFATokenError",
    "MissingMFACredentialsError",
    "InvalidCredentialsError",
    "NetworkPolicyError",
    "NotFoundError",
    "AuthenticationError",
]
