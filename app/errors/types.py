"""Error code contracts.

Defines a protocol for exceptions that carry a stable internal ErrorCode
and a lightweight carrier implementation to wrap foreign exceptions.
"""

from __future__ import annotations

from typing import Protocol

from enums import ErrorCode


class HasErrorCode(Protocol):
    """Exceptions that expose a stable internal error code."""

    def get_error_code(self) -> ErrorCode:
        """Return internal error code."""
        ...


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

    def get_error_code(self) -> ErrorCode:
        return self._code

    @property
    def cause(self) -> Exception:
        return self._cause
