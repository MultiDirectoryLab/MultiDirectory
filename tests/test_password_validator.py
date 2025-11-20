"""Test Password Validator.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime, timedelta

import pytest

from ldap_protocol.policies.password import PasswordPolicyValidator
from ldap_protocol.policies.password.ban_word_repository import (
    PasswordBanWordRepository,
)
from ldap_protocol.utils.helpers import dt_to_ft


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_min_letters_count(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for minimum letters count."""
    password_policy_validator.setup_language("Latin")
    validator = password_policy_validator.min_letters_count(2)
    assert not await validator.validate("1234")
    assert await validator.validate("abc")
    assert not await validator.validate("1234!@#")
    assert await validator.validate("a1b2")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_language_latin(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for no OTP-like suffix."""
    password_policy_validator.setup_language("Latin")
    password_policy_validator.language()
    assert not await password_policy_validator.validate("кириллица")
    assert not await password_policy_validator.validate("__кири_лли!ца0")
    assert await password_policy_validator.validate("latin")
    assert await password_policy_validator.validate("3_latin!")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_language_cyrillic(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for no OTP-like suffix."""
    password_policy_validator.setup_language("Cyrillic")
    password_policy_validator.language()
    assert not await password_policy_validator.validate("latin")
    assert not await password_policy_validator.validate("3_latin!")
    assert await password_policy_validator.validate("кириллица")
    assert await password_policy_validator.validate("__кири_лли!ца0")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_min_digits_count(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for minimum digits count."""
    validator = password_policy_validator.min_digits_count(2)
    assert await validator.validate("abc123")
    assert not await validator.validate("abcdef")
    assert not await validator.validate("")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_min_uppercase_letters_count(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for minimum uppercase letters count."""
    password_policy_validator.setup_language("Latin")
    validator = password_policy_validator.min_uppercase_letters_count(2)
    assert await validator.validate("ABC")
    assert not await validator.validate("aBc")
    assert not await validator.validate("abc")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_min_lowercase_letters_count(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for minimum lowercase letters count."""
    password_policy_validator.setup_language("Latin")
    validator = password_policy_validator.min_lowercase_letters_count(2)
    assert not await validator.validate("ABC")
    assert await validator.validate("aBc")
    assert await validator.validate("abc")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_not_equal_any_ban_word(
    password_policy_validator: PasswordPolicyValidator,
    password_ban_word_repository: PasswordBanWordRepository,
) -> None:
    """Test password validator for not equaling banned words into password."""
    password_policy_validator.setup_language("Latin")
    validator = password_policy_validator.not_equal_any_ban_word(
        password_ban_word_repository,
    )
    assert not await validator.validate("alex")
    assert not await validator.validate("aLex")
    assert not await validator.validate("ALEX")
    assert await validator.validate("prefix_alex_suffix")
    assert await validator.validate("_alex_sUffix_120*!_")
    assert await validator.validate("_ALex_sUffix_120*!_")
    assert await validator.validate("_12PrEf!x_alex")
    assert await validator.validate("_12PrEf!x_ALex")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_not_contain_any_ban_word(
    password_policy_validator: PasswordPolicyValidator,
    password_ban_word_repository: PasswordBanWordRepository,
) -> None:
    """Test password validator for not containing banned words into password."""  # noqa: E501
    password_policy_validator.setup_language("Latin")
    validator = password_policy_validator.not_contain_any_ban_word(
        password_ban_word_repository,
    )
    assert not await validator.validate("prefix_alex_suffix")
    assert not await validator.validate("_alex_sUffix_120*!_")
    assert not await validator.validate("_ALex_sUffix_120*!_")
    assert not await validator.validate("_12PrEf!x_alex")
    assert not await validator.validate("_12PrEf!x_ALex")
    assert await validator.validate("!coRR3c7_P@$$w0rd")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_min_special_symbols_count(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for minimum special symbols count."""
    password_policy_validator.setup_language("Latin")
    validator = password_policy_validator.min_special_symbols_count(2)
    assert not await validator.validate("abc@")
    assert not await validator.validate("abc")
    assert await validator.validate("!@#abc")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_min_unique_symbols_count(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for minimum unique symbols count."""
    validator = password_policy_validator.min_unique_symbols_count(2)
    assert await validator.validate("aaaaa!!!!!33333333")
    assert await validator.validate("aaaaa!!!!!")
    assert not await validator.validate("aaaaaa")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_max_sequential_keyboard_symbols_count(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for maximum sequential keyboard symbols count."""  # noqa: E501
    password_policy_validator.setup_language("Latin")
    validator = (
        password_policy_validator.max_sequential_keyboard_symbols_count(4)
    )
    assert not await validator.validate("qwerty")
    assert not await validator.validate("QWERTY")
    assert not await validator.validate("PQWE")
    assert not await validator.validate("QPOI")
    assert not await validator.validate('SA":')
    assert not await validator.validate("1234")
    assert not await validator.validate("4321")
    assert not await validator.validate("8901")
    assert not await validator.validate("1098")
    assert not await validator.validate("18_!qwerty")
    assert not await validator.validate("18_!QWERTY")
    assert not await validator.validate("18_!QwErTy")
    assert not await validator.validate("qwerty!_81")
    assert not await validator.validate("18qwerty!_")
    assert await validator.validate("QWE1rty")
    assert await validator.validate("123q456")
    assert await validator.validate("q1w2e3r4t5y")
    assert await validator.validate("q.w1e2r.t.y")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_max_sequential_alphabet_symbols_count(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for maximum sequential alphabet symbols count."""  # noqa: E501
    password_policy_validator.setup_language("Latin")

    validator = (
        password_policy_validator.max_sequential_alphabet_symbols_count(4)
    )
    assert not await validator.validate("18abcdef!_")
    assert not await validator.validate("18abCDef!_")
    assert not await validator.validate("18yzAB!_")
    assert not await validator.validate("zabc")
    assert not await validator.validate("cbaz")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_max_repeating_symbols_in_row_count(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for maximum repeating symbols in row count."""
    validator = password_policy_validator.max_repeating_symbols_in_row_count(3)
    assert not await validator.validate("33aaa!!!3")
    assert await validator.validate("33a!3")
    assert await validator.validate("abcdef")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_min_max_length(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for min and max length."""
    validator = password_policy_validator.min_length(3).max_length(5)
    assert not await validator.validate("ab")
    assert await validator.validate("abc")
    assert await validator.validate("abcd")
    assert await validator.validate("abcde")
    assert not await validator.validate("abcdef")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_no_otp_like_suffix(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator for no OTP-like suffix."""
    validator = password_policy_validator.not_otp_like_suffix()
    assert not await validator.validate("abc123456")
    assert await validator.validate("abc12345")
    assert await validator.validate("abc1a23456")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_chained_rules(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator with chained rules."""
    password_policy_validator.setup_language("Latin")
    validator = (
        password_policy_validator
        .min_letters_count(2)
        .min_digits_count(2)
        .min_length(5)
        .max_length(10)
    )  # fmt: skip
    assert await validator.validate("abc12")
    assert not await validator.validate("abc")
    assert not await validator.validate("12345")
    assert not await validator.validate("abc123456789")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_min_age(
    password_policy_validator: PasswordPolicyValidator,
) -> None:
    """Test password validator with chained rules."""
    required_date = str(dt_to_ft(datetime.now() - timedelta(days=5)))

    validator = password_policy_validator.min_age(0, required_date)
    assert await validator.validate("abc123")

    validator = password_policy_validator.min_age(5, required_date)
    assert await validator.validate("abc123456789")

    validator = password_policy_validator.min_age(10, required_date)
    assert not await validator.validate("abc123456789")
