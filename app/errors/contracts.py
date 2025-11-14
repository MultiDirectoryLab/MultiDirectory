"""Error code contracts.

Defines a protocol for exceptions that carry a stable internal ErrorCode
and a lightweight carrier implementation to wrap foreign exceptions.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Protocol, runtime_checkable

from enums import ErrorCode


@runtime_checkable
class HasErrorCode(Protocol):
    """Exceptions that expose a stable internal error code."""

    def get_error_code(self) -> ErrorCode:
        """Return internal error code."""


class ErrorCodeCarrierError(Exception):
    """Wrap a cause exception and carry an explicit ErrorCode.

    Prefer composition over inheritance to avoid changing exception
    hierarchy.
    """

    def __init__(self, cause: Exception, code: ErrorCode) -> None:
        """Create a carrier with original cause and internal code."""
        super().__init__(str(cause))
        self._cause = cause
        self._code = code
        self.__cause__ = cause
        self._original_class = type(self)

    def __repr__(self) -> str:
        """Return repr of the original exception."""
        return repr(self._cause)

    def __str__(self) -> str:
        """Return str of the original exception."""
        return str(self._cause)

    def __getattribute__(self, name: str) -> object:
        """Intercept __class__ access to return original exception class."""
        if name == "__class__":
            return type(object.__getattribute__(self, "_cause"))
        return object.__getattribute__(self, name)

    def get_error_code(self) -> ErrorCode:
        """Return internal error code."""
        return object.__getattribute__(self, "_code")

    @property
    def cause(self) -> Exception:
        """Return the original exception."""
        return object.__getattribute__(self, "_cause")
