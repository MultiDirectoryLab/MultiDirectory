"""Errors package.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .base import (
    ERROR_MAP_TYPE,
    BaseDomainException,
    BaseErrorTranslator,
    DishkaErrorAwareRoute,
)
from .enums import ErrorStatusCodes

__all__ = [
    "BaseDomainException",
    "BaseErrorTranslator",
    "ErrorStatusCodes",
    "ERROR_MAP_TYPE",
    "DishkaErrorAwareRoute",
]
