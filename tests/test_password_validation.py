"""Test Password Validator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime, timedelta

import pytest

from ldap_protocol.policies.password import PasswordPolicyValidator
from ldap_protocol.utils.helpers import dt_to_ft


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_min_max_length() -> None:
    """Test password validator for min and max length."""
    validator = PasswordPolicyValidator().min_length(3)
    assert not await validator.validate("ab")
    assert await validator.validate("abc")
    assert await validator.validate("abcd")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_no_otp_like_suffix() -> None:
    """Test password validator for no OTP-like suffix."""
    validator = PasswordPolicyValidator().not_otp_like_suffix()
    assert not await validator.validate("abc123456")
    assert await validator.validate("abc12345")
    assert await validator.validate("abc1a23456")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_min_age() -> None:
    """Test password validator with chained rules."""
    required_date = str(dt_to_ft(datetime.now() - timedelta(days=5)))

    validator = PasswordPolicyValidator().min_age(0, required_date)
    assert await validator.validate("abc123")

    validator = PasswordPolicyValidator().min_age(5, required_date)
    assert await validator.validate("abc123456789")

    validator = PasswordPolicyValidator().min_age(10, required_date)
    assert not await validator.validate("abc123456789")
