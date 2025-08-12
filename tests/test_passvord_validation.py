"""Test Password Validator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime, timedelta

import pytest

from ldap_protocol.utils.helpers import dt_to_ft
from password_manager import PasswordValidator


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_min_max_length() -> None:
    """Test password validator for min and max length."""
    schema = PasswordValidator().min_length(3)
    assert not await schema.validate("ab")
    assert await schema.validate("abc")
    assert await schema.validate("abcd")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_no_otp_like_suffix() -> None:
    """Test password validator for no OTP-like suffix."""
    schema = PasswordValidator().not_otp_like_suffix()
    assert not await schema.validate("abc123456")
    assert await schema.validate("abc12345")
    assert await schema.validate("abc1a23456")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_min_age() -> None:
    """Test password validator with chained rules."""
    required_date = str(dt_to_ft(datetime.now() - timedelta(days=5)))

    schema = PasswordValidator().min_age(0, required_date)
    assert await schema.validate("abc123")

    schema = PasswordValidator().min_age(5, required_date)
    assert await schema.validate("abc123456789")

    schema = PasswordValidator().min_age(10, required_date)
    assert not await schema.validate("abc123456789")
