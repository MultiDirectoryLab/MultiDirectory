"""Adapters package for FastAPI adapters for authentication and MFA managers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .identity import IdentityFastAPIAdapter
from .mfa import MFAFastAPIAdapter

__all__ = [
    "IdentityFastAPIAdapter",
    "MFAFastAPIAdapter",
]
