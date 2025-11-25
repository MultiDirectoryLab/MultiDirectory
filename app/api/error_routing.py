"""Error routing.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from enum import IntEnum

from dishka.integrations.fastapi import DishkaRoute
from fastapi_error_map.routing import ErrorAwareRoute
from fastapi_error_map.rules import Rule
from fastapi_error_map.translators import ErrorTranslator

from enums import DoaminCodes
from errors import BaseDomainException

ERROR_MAP_TYPE = dict[type[Exception], int | Rule] | None


@dataclass
class ErrorResponse:
    """Error response."""

    type: str
    detail: str
    domain_code: DoaminCodes
    error_code: IntEnum


class DishkaErrorAwareRoute(ErrorAwareRoute, DishkaRoute):
    """Route class that combines ErrorAwareRoute and DishkaRoute."""


class DomainErrorTranslator(ErrorTranslator[ErrorResponse]):
    """DNS error translator."""

    domain_code: DoaminCodes

    def __init__(self, domain_code: DoaminCodes) -> None:
        """Initialize error translator."""
        self.domain_code = domain_code

    @property
    def error_response_model_cls(self) -> type[ErrorResponse]:
        return ErrorResponse

    def from_error(self, err: Exception) -> ErrorResponse:
        """Translate exception to error response."""
        if not isinstance(err, BaseDomainException):
            raise TypeError(f"Expected BaseDomainException, got {type(err)}")

        return ErrorResponse(
            type=type(err).__name__,
            detail=str(err),
            domain_code=self.domain_code,
            error_code=err.code,
        )
