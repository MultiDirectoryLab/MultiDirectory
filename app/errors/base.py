"""Errors base.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from enum import Enum

from dishka.integrations.fastapi import DishkaRoute
from fastapi_error_map.routing import ErrorAwareRoute
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
    status_code: str
    domain_code: str


class DishkaErrorAwareRoute(ErrorAwareRoute, DishkaRoute):
    """Route class that combines ErrorAwareRoute and DishkaRoute."""


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
            status_code=str(err.status_code),
            domain_code=self.domain_code,
        )
