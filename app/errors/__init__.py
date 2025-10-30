"""Errors package.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .catalog import ErrorCatalog
from .contracts import ErrorCodeCarrierError, HasErrorCode
from .http_mapper import HttpCodeMapper

__all__ = [
    "ErrorCatalog",
    "ErrorCodeCarrierError",
    "HasErrorCode",
    "HttpCodeMapper",
]
