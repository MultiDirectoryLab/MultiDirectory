"""Tests for exception classes.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import importlib

import pytest
from loguru import logger

from api.error_routing import BaseDomainException
from ldap_protocol.dhcp.exceptions import (
    DHCPEntryAddError,
    DHCPEntryDeleteError,
    DHCPEntryNotFoundError,
    DHCPEntryUpdateError,
)
from ldap_protocol.identity.exceptions import (
    ErrorCodes as AuthErrorCodes,
    IdentityUserNotFoundError,
)
from ldap_protocol.policies.audit.exceptions import (
    AuditAlreadyExistsError,
    AuditNotFoundError,
)

from . import parser


def test_base_domain_exception_requires_code_and_status_code() -> None:
    """Test that BaseDomainException requires attributes."""
    with pytest.raises(
        AttributeError,
        match="code must be set",
    ):

        class InvalidError(BaseDomainException):
            """Invalid error without code."""


def test_error_exception_message() -> None:
    """Test that exceptions can be created with custom messages."""
    error = IdentityUserNotFoundError("User john@example.com not found")
    assert str(error) == "User john@example.com not found"
    assert error.code == AuthErrorCodes.USER_NOT_FOUND_ERROR


def test_audit_exceptions_in_error_map() -> None:
    """Test that audit exceptions are properly mapped in error_map."""
    router_module = importlib.import_module("api.audit.router")
    error_map = getattr(router_module, "error_map", {})

    assert AuditNotFoundError in error_map, (
        "AuditNotFoundError must be in audit router error_map",
    )
    assert AuditAlreadyExistsError in error_map, (
        "AuditAlreadyExistsError must be in audit router error_map",
    )

    assert AuditNotFoundError.code.value == 1
    assert AuditAlreadyExistsError.code.value == 2


def test_dhcp_exceptions_in_error_map() -> None:
    """Test that DHCP exceptions are properly mapped in error_map."""
    router_module = importlib.import_module("api.dhcp.router")
    error_map = getattr(router_module, "error_map", {})

    expected_exceptions: set[type[BaseDomainException]] = {
        DHCPEntryNotFoundError,
        DHCPEntryDeleteError,
        DHCPEntryAddError,
        DHCPEntryUpdateError,
    }

    for exc_class in expected_exceptions:
        assert exc_class in error_map, (
            f"{exc_class.__name__} must be in DHCP router error_map",
        )
        assert exc_class.code.value != 0, (
            f"{exc_class.__name__} must not use BASE_ERROR code",
        )


async def test_error_parser() -> None:
    """Test that error parser works correctly."""
    data = await parser.get_router_confs()
    for router_conf in data:
        logger.error(router_conf.error_map)
        logger.error(router_conf.translator)
        logger.error(router_conf.domain_name)
