"""Errors package.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .base import BaseDomainException, BaseErrorTranslator
from .enums import ErrorStatusCodes

__all__ = [
    "BaseDomainException",
    "BaseErrorTranslator",
    "ErrorStatusCodes",
]
