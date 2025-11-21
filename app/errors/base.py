"""Errors base.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from enum import Enum

from fastapi_error_map.translators import ErrorTranslator

from errors.enums import ErrorCodeParts, ErrorStatusCodes


class AbstractException(Exception):  # noqa N818
    """Base exception."""

    code: Enum
    status_code: ErrorStatusCodes


@dataclass
class ErrorResponse:
    """Error response."""

    type: str
    message: str
    error_code: str


class BaseErrorTranslator(ErrorTranslator[ErrorResponse]):
    """DNS error translator."""

    domain_code: ErrorCodeParts

    @property
    def error_response_model_cls(self) -> type[ErrorResponse]:
        return ErrorResponse

    def from_error(self, err: Exception) -> ErrorResponse:
        """Translate exception to error response."""
        if not isinstance(err, AbstractException):
            raise TypeError(f"Expected AbstractException, got {type(err)}")
        return ErrorResponse(
            type=type(err).__name__,
            message=str(err),
            error_code=self.make_code(err),
        )

    def make_code(self, err: AbstractException) -> str:
        """Make code."""
        return f"{str(err.status_code)}{self.domain_code}{err.code}"
