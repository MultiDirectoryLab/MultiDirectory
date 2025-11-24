"""Tests for exception classes.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import inspect

import pytest

from errors import BaseDomainException, ErrorStatusCodes
from ldap_protocol.dhcp.exceptions import DHCPError
from ldap_protocol.identity.exceptions.auth import (
    AuthError,
    ErrorCodes as AuthErrorCodes,
    UserNotFoundError,
)
from ldap_protocol.identity.exceptions.mfa import (
    InvalidCredentialsError,
    MFAError,
)
from ldap_protocol.kerberos.exceptions import KerberosError
from ldap_protocol.policies.audit.exceptions import (
    AuditError,
    AuditNotFoundError,
)
from ldap_protocol.policies.network.exceptions import NetworkPolicyError
from ldap_protocol.policies.password.exceptions import PasswordPolicyError
from ldap_protocol.session_storage.exceptions import SessionStorageError

BASE_ERROR_CLASSES = [
    AuditError,
    AuthError,
    MFAError,
    KerberosError,
    NetworkPolicyError,
    PasswordPolicyError,
    DHCPError,
    SessionStorageError,
]

CONCRETE_ERROR_CLASSES = [
    AuditNotFoundError,
    UserNotFoundError,
    InvalidCredentialsError,
]


@pytest.mark.parametrize(
    "error_class",
    BASE_ERROR_CLASSES + CONCRETE_ERROR_CLASSES,
)
def test_error_inherits_from_base_domain_exception(
    error_class: type[BaseDomainException],
) -> None:
    """Test that all error classes inherit from BaseDomainException."""
    assert issubclass(error_class, BaseDomainException)


@pytest.mark.parametrize(
    "error_class",
    BASE_ERROR_CLASSES + CONCRETE_ERROR_CLASSES,
)
def test_error_has_code_attribute(
    error_class: type[BaseDomainException],
) -> None:
    """Test that all error classes have code attribute."""
    assert hasattr(error_class, "code")
    assert error_class.code is not None


@pytest.mark.parametrize(
    "error_class",
    BASE_ERROR_CLASSES + CONCRETE_ERROR_CLASSES,
)
def test_error_has_status_code_attribute(
    error_class: type[BaseDomainException],
) -> None:
    """Test that all error classes have status_code attribute."""
    assert hasattr(error_class, "status_code")
    assert isinstance(error_class.status_code, ErrorStatusCodes)


@pytest.mark.parametrize(
    "error_class",
    BASE_ERROR_CLASSES + CONCRETE_ERROR_CLASSES,
)
def test_error_can_be_instantiated(
    error_class: type[BaseDomainException],
) -> None:
    """Test that all error classes can be instantiated with a message."""
    error = error_class("Test error message")
    assert str(error) == "Test error message"
    assert error.code is not None
    assert error.status_code is not None


@pytest.mark.parametrize(
    "error_class",
    BASE_ERROR_CLASSES + CONCRETE_ERROR_CLASSES,
)
def test_error_code_matches_enum(
    error_class: type[BaseDomainException],
) -> None:
    """Test that error code matches the corresponding enum value."""
    module = inspect.getmodule(error_class)
    if module:
        error_codes_class = getattr(module, "ErrorCodes", None)
        if error_codes_class:
            assert error_class.code in error_codes_class


def test_base_domain_exception_requires_code_and_status_code() -> None:
    """Test that BaseDomainException requires attributes."""

    class InvalidError(BaseDomainException):
        """Invalid error without code and status_code."""

    with pytest.raises(
        AttributeError,
        match="code and status_code must be set",
    ):
        pass


def test_error_exception_message() -> None:
    """Test that exceptions can be created with custom messages."""
    error = UserNotFoundError("User john@example.com not found")
    assert str(error) == "User john@example.com not found"
    assert error.code == AuthErrorCodes.USER_NOT_FOUND_ERROR
    assert error.status_code == ErrorStatusCodes.BAD_REQUEST


def test_error_exception_inheritance_chain() -> None:
    """Test that error inheritance chain is correct."""
    assert issubclass(UserNotFoundError, AuthError)
    assert issubclass(AuthError, BaseDomainException)
    assert issubclass(BaseDomainException, Exception)


@pytest.mark.parametrize("error_class", CONCRETE_ERROR_CLASSES)
def test_error_code_is_not_base_error(
    error_class: type[BaseDomainException],
) -> None:
    """Test that concrete error classes don't use BASE_ERROR code."""
    error = error_class("Test")
    assert error.code.value != 0, (
        f"{error_class.__name__} should not use BASE_ERROR"
    )
