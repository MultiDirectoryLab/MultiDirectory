"""Adapters package for FastAPI adapters for authentication and MFA managers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .current_user_gateway import CurrentUserGateway
from .identity import IdentityFastAPIAdapter
from .mfa import MFAFastAPIAdapter
from .session_gateway import SessionFastAPIGateway

__all__ = [
    "IdentityFastAPIAdapter",
    "MFAFastAPIAdapter",
    "SessionFastAPIGateway",
    "CurrentUserGateway",
]
