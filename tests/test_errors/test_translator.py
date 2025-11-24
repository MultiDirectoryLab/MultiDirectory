"""Tests for error translator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest

from enums import ProjectPartCodes
from errors import BaseDomainException, BaseErrorTranslator, ErrorStatusCodes
from errors.base import ErrorResponse
from ldap_protocol.identity.exceptions.auth import UserNotFoundError
from ldap_protocol.policies.audit.exceptions import AuditNotFoundError


class TestErrorTranslator(BaseErrorTranslator):
    """Test error translator."""

    domain_code = ProjectPartCodes.AUDIT


def test_error_translator_from_error() -> None:
    """Test that error translator converts exception to ErrorResponse."""
    translator = TestErrorTranslator()
    error = AuditNotFoundError("Audit policy not found")

    response = translator.from_error(error)

    assert isinstance(response, ErrorResponse)
    assert response.type == "AuditNotFoundError"
    assert response.detail == "Audit policy not found"
    assert response.status_code == ErrorStatusCodes.BAD_REQUEST.value
    assert response.domain_code == ProjectPartCodes.AUDIT.value
    assert response.error_code == error.code.value


def test_translator_raises_domain_error() -> None:
    """Test that translator raises TypeError for non-BaseDomainException."""
    translator = TestErrorTranslator()

    with pytest.raises(TypeError, match="Expected BaseDomainException"):
        translator.from_error(ValueError("Not a domain exception"))


@pytest.mark.parametrize(
    ("error", "expected_status_code"),
    [
        (UserNotFoundError("User not found"), ErrorStatusCodes.BAD_REQUEST),
        (AuditNotFoundError("Audit not found"), ErrorStatusCodes.BAD_REQUEST),
    ],
)
def test_error_translator_status_code_mapping(
    error: BaseDomainException,
    expected_status_code: ErrorStatusCodes,
) -> None:
    """Test that error translator maps status codes correctly."""
    translator = TestErrorTranslator()
    response = translator.from_error(error)

    assert response.status_code == expected_status_code.value


def test_error_translator_domain_code() -> None:
    """Test that error translator uses correct domain code."""
    translator = TestErrorTranslator()
    error = AuditNotFoundError("Test")

    response = translator.from_error(error)

    assert response.domain_code == ProjectPartCodes.AUDIT.value


def test_error_response_dataclass() -> None:
    """Test that ErrorResponse is a proper dataclass."""
    response = ErrorResponse(
        type="TestError",
        detail="Test detail",
        status_code=400,
        domain_code=1,
        error_code=2,
    )

    assert response.type == "TestError"
    assert response.detail == "Test detail"
    assert response.status_code == 400
    assert response.domain_code == 1
    assert response.error_code == 2
