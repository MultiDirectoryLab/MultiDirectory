"""Errors package.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .base import AbstractException, BaseErrorTranslator
from .enums import ErrorCodeParts, ErrorStatusCodes

__all__ = [
    "AbstractException",
    "ErrorCodeParts",
    "BaseErrorTranslator",
    "ErrorStatusCodes",
]
