"""Tests for LDF files validator."""

import pytest

from ldap_protocol.ldif_directory_exchange.ldf_files_validator import (
    LdfFilesValidationError,
    LdfFilesValidator,
)


def test_execute_validates_and_sorts() -> None:
    """Validate and sort LDF file paths."""
    validator = LdfFilesValidator()
    paths = [
        "/extra/sch16.ldf",
        "/extra/sch14.ldf",
        "/extra/sch15.ldf",
    ]

    result = validator.execute(paths)

    assert result == [
        "/extra/sch14.ldf",
        "/extra/sch15.ldf",
        "/extra/sch16.ldf",
    ]


def test_execute_rejects_invalid_name() -> None:
    """Reject invalid file name."""
    validator = LdfFilesValidator()
    paths = [
        "/extra/sch14_err_name.ldf",
        "/extra/sch15.ldf",
    ]

    with pytest.raises(LdfFilesValidationError):
        validator.execute(paths)


def test_execute_rejects_missing_number() -> None:
    """Reject missing version number."""
    validator = LdfFilesValidator()
    paths = [
        "/extra/sch14.ldf",
        "/extra/sch16.ldf",
    ]

    with pytest.raises(LdfFilesValidationError):
        validator.execute(paths)


def test_execute_rejects_wrong_start() -> None:
    """Reject list that does not start with sch14."""
    validator = LdfFilesValidator()
    paths = [
        "/extra/sch15.ldf",
        "/extra/sch16.ldf",
    ]

    with pytest.raises(LdfFilesValidationError):
        validator.execute(paths)
