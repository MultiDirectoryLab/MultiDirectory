"""Errors base.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum


class BaseDomainException(Exception):  # noqa N818
    """Base exception."""

    code: IntEnum

    def __init_subclass__(cls) -> None:
        """Initialize subclass."""
        super().__init_subclass__()

        if not hasattr(cls, "code") or not hasattr(cls, "status_code"):
            raise AttributeError("code and status_code must be set")
