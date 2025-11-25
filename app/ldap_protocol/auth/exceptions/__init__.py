"""Exception package for authentication and MFA related errors.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .mfa import (
    InvalidCredentialsError,
    MFARequiredError,
    MFATokenError,
    MissingMFACredentialsError,
    NetworkPolicyError,
    NotFoundError,
)

__all__ = [
    "MFARequiredError",
    "MFATokenError",
    "MissingMFACredentialsError",
    "InvalidCredentialsError",
    "NetworkPolicyError",
    "NotFoundError",
]
