"""Test RFC5424Serializer.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re
from datetime import datetime, timezone

import pytest

from ldap_protocol.policies.audit.events.service_senders.rfc5424_serializer import (  # noqa: E501
    RFC5424Serializer,
)


@pytest.fixture
def serializer() -> RFC5424Serializer:
    """Create serializer instance."""
    return RFC5424Serializer(
        app_name="TestApp",
        facility="authpriv",
    )


@pytest.mark.parametrize(
    ("facility", "severity", "expected_severity"),
    [
        ("kernel", 5, 5),
        ("user", 3, 11),
        ("authpriv", 6, 86),
        ("local0", 7, 135),
        ("local7", 2, 186),
    ],
)
def test_format_priority(
    facility: str,
    severity: int,
    expected_severity: int,
) -> None:
    """Test _format_priority with different facilities and severities."""
    serializer = RFC5424Serializer(app_name="Test", facility=facility)
    severity = serializer._format_severity(severity)  # noqa: SLF001
    assert severity == expected_severity


@pytest.mark.parametrize(
    "invalid_severity",
    [-1, 8, 10, 100],
)
def test_format_priority_invalid_severity(
    serializer: RFC5424Serializer,
    invalid_severity: int,
) -> None:
    """Test _format_priority with invalid severity values."""
    with pytest.raises(NotImplementedError, match="Severity must be 0-7"):
        serializer._format_severity(invalid_severity)  # noqa: SLF001


def test_format_timestamp(serializer: RFC5424Serializer) -> None:
    """Test _format_timestamp formats timestamp correctly."""
    dt = datetime(2025, 12, 23, 10, 30, 45, 123000, tzinfo=timezone.utc)
    timestamp = dt.timestamp()

    result = serializer._format_timestamp(timestamp)  # noqa: SLF001

    assert result == "2025-12-23T10:30:45.123Z"
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", result)


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("server01.example.com", "server01.example.com"),
        ("a" * 300, "a" * 255),
    ],
)
def test_format_hostname(
    serializer: RFC5424Serializer,
    hostname: str,
    expected: str,
) -> None:
    """Test _format_hostname with various inputs."""
    result = serializer._format_hostname(hostname)  # noqa: SLF001
    assert result == expected


def test_format_hostname_with_none(serializer: RFC5424Serializer) -> None:
    """Test _format_hostname with None uses system hostname."""
    result = serializer._format_hostname(None)  # noqa: SLF001
    assert result != "-"
    assert len(result) > 0


@pytest.mark.parametrize(
    ("value", "max_length", "expected"),
    [
        ("test_value", 100, "test_value"),
        (None, 100, "-"),
        ("", 100, "-"),
        ("abcdefghij", 5, "abcde"),
        ("test\x00\x01value\n\r", 100, "testvalue"),
        ("\x00\x01\x02\n\r", 100, "-"),
    ],
)
def test_format_field(
    serializer: RFC5424Serializer,
    value: str | None,
    max_length: int,
    expected: str,
) -> None:
    """Test _format_field with various inputs."""
    result = serializer._format_field(value, max_length)  # noqa: SLF001
    assert result == expected


@pytest.mark.parametrize(
    ("data", "expected_result"),
    [
        ({}, "-"),
        ({"username": "admin"}, '[audit@32473 username="admin"]'),
    ],
)
def test_format_structured_data(
    serializer: RFC5424Serializer,
    data: dict,
    expected_result: str,
) -> None:
    """Test _format_structured_data with various inputs."""
    result = serializer._format_structured_data(data)  # noqa: SLF001
    assert result == expected_result


def test_format_structured_data_multiple_params(
    serializer: RFC5424Serializer,
) -> None:
    """Test _format_structured_data with multiple parameters."""
    data = {
        "username": "admin",
        "ip": "192.168.1.100",
        "action": "login",
    }
    result = serializer._format_structured_data(data)  # noqa: SLF001

    assert result.startswith("[audit@32473")
    assert result.endswith("]")
    assert 'username="admin"' in result
    assert 'ip="192.168.1.100"' in result
    assert 'action="login"' in result


@pytest.mark.parametrize(
    ("input_name", "expected"),
    [
        ("valid_name123", "valid_name123"),
        ("user name", "username"),
        ("user=name", "username"),
        ('user"name', "username"),
        ("user]name", "username"),
    ],
)
def test_sanitize_param_name(
    serializer: RFC5424Serializer,
    input_name: str,
    expected: str,
) -> None:
    """Test _sanitize_param_name with various inputs."""
    result = serializer._sanitize_param_name(input_name)  # noqa: SLF001
    assert result == expected


@pytest.mark.parametrize(
    ("input_value", "expected"),
    [
        ("simple text", "simple text"),
        ("path\\to\\file", "path\\\\to\\\\file"),
        ('say "hello"', r"say \"hello\""),
        ("array[index]", r"array[index\]"),
        (
            'Test "quote" and \\backslash and ]bracket',
            r"Test \"quote\" and \\backslash and \]bracket",
        ),
    ],
)
def test_escape_param_value(
    serializer: RFC5424Serializer,
    input_value: str,
    expected: str,
) -> None:
    """Test _escape_param_value with various special characters."""
    result = serializer._escape_param_value(input_value)  # noqa: SLF001
    assert result == expected


@pytest.mark.parametrize(
    ("input_msg", "expected"),
    [
        ("User logged in", " \ufeffUser logged in"),
        (None, ""),
        ("", ""),
    ],
)
def test_format_message(
    serializer: RFC5424Serializer,
    input_msg: str | None,
    expected: str,
) -> None:
    """Test _format_message with various inputs."""
    result = serializer._format_message(input_msg)  # noqa: SLF001
    assert result == expected
