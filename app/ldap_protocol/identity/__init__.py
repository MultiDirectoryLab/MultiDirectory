"""Identity package."""

from .exceptions import (
    IdentityAlreadyConfiguredError,
    IdentityForbiddenError,
    IdentityLoginFailedError,
    IdentityPasswordPolicyError,
    IdentityUnauthorizedError,
    IdentityUserNotFoundError,
    IdentityValidationError,
)
from .provider import IdentityProvider

__all__ = [
    "IdentityProvider",
    "IdentityUnauthorizedError",
    "IdentityAlreadyConfiguredError",
    "IdentityForbiddenError",
    "IdentityLoginFailedError",
    "IdentityPasswordPolicyError",
    "IdentityUserNotFoundError",
    "IdentityValidationError",
]
