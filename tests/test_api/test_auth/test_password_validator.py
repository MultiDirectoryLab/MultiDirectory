"""Test Password Validator.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from password_validator.validator import PasswordValidator


@pytest.mark.asyncio
async def test_password_validator_min_letters_count() -> None:
    """Test password validator for minimum letters count."""
    schema = PasswordValidator().min_letters_count(2)
    assert not await schema.validate("1234")
    assert await schema.validate("abc")
    assert not await schema.validate("1234!@#")
    assert await schema.validate("a1b2")


@pytest.mark.asyncio
async def test_password_validator_min_digits_count() -> None:
    """Test password validator for minimum digits count."""
    schema = PasswordValidator().min_digits_count(2)
    assert await schema.validate("abc123")
    assert not await schema.validate("abcdef")
    assert not await schema.validate("")


@pytest.mark.asyncio
async def test_password_validator_min_uppercase_letters_count() -> None:
    """Test password validator for minimum uppercase letters count."""
    schema = PasswordValidator().min_uppercase_letters_count(2)
    assert await schema.validate("ABC")
    assert not await schema.validate("aBc")
    assert not await schema.validate("abc")


@pytest.mark.asyncio
async def test_password_validator_min_lowercase_letters_count() -> None:
    """Test password validator for minimum lowercase letters count."""
    schema = PasswordValidator().min_lowercase_letters_count(2)
    assert not await schema.validate("ABC")
    assert await schema.validate("aBc")
    assert await schema.validate("abc")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_not_contains_in_common_list(
    session: AsyncSession,
) -> None:
    """Test password validator for not containing in common list."""
    schema = PasswordValidator().not_contains_in_common_list(session)
    assert not await schema.validate("helpme")
    assert await schema.validate("not_common_Passw0Rd")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_validator_not_contain_ban_word(
    session: AsyncSession,
) -> None:
    """Test password validator for not containing banned words into password."""  # noqa: E501
    schema = PasswordValidator().not_contain_ban_word(session)
    assert not await schema.validate("prefix_alex_suffix")
    assert await schema.validate("!coRR3c7_P@$$w0rd")


@pytest.mark.asyncio
async def test_password_validator_min_special_symbols_count() -> None:
    """Test password validator for minimum special symbols count."""
    schema = PasswordValidator().min_special_symbols_count(2)
    assert not await schema.validate("abc@")
    assert not await schema.validate("abc")
    assert await schema.validate("!@#abc")


@pytest.mark.asyncio
async def test_password_validator_min_unique_symbols_count() -> None:
    """Test password validator for minimum unique symbols count."""
    schema = PasswordValidator().min_unique_symbols_count(2)
    assert await schema.validate("aaaaa!!!!!33333333")
    assert await schema.validate("aaaaa!!!!!")
    assert not await schema.validate("aaaaaa")


@pytest.mark.asyncio
async def test_password_validator_max_sequential_keyboard_symbols_count() -> (
    None
):
    """Test password validator for maximum sequential keyboard symbols count."""  # noqa: E501
    schema = PasswordValidator().max_sequential_keyboard_symbols_count(4)
    assert not await schema.validate("qwerty")
    assert not await schema.validate("QWERTY")
    assert not await schema.validate("PQWE")
    assert not await schema.validate("QPOI")
    assert not await schema.validate("1234")
    assert not await schema.validate("4321")
    assert not await schema.validate("8901")
    assert not await schema.validate("1098")
    assert not await schema.validate("18_!qwerty")
    assert not await schema.validate("18_!QWERTY")
    assert not await schema.validate("18_!QwErTy")
    assert not await schema.validate("qwerty!_81")
    assert not await schema.validate("18qwerty!_")
    assert await schema.validate("QWE1rty")
    assert await schema.validate("123q456")
    assert await schema.validate("q1w2e3r4t5y")
    assert await schema.validate("q.w1e2r.t.y")


@pytest.mark.asyncio
async def test_password_validator_max_sequential_alphabet_symbols_count() -> (
    None
):
    """Test password validator for maximum sequential alphabet symbols count."""  # noqa: E501
    schema = PasswordValidator().max_sequential_alphabet_symbols_count(4)
    assert not await schema.validate("18abcdef!_")
    assert not await schema.validate("18abCDef!_")
    assert not await schema.validate("18yzAB!_")
    assert not await schema.validate("zabc")
    assert not await schema.validate("cbaz")


@pytest.mark.asyncio
async def test_password_validator_max_repeating_symbols_in_row_count() -> None:
    """Test password validator for maximum repeating symbols in row count."""
    schema = PasswordValidator().max_repeating_symbols_in_row_count(2)
    assert not await schema.validate("aa!!3")
    assert await schema.validate("a!3")
    assert await schema.validate("abcdef")


@pytest.mark.asyncio
async def test_password_validator_min_max_length() -> None:
    """Test password validator for min and max length."""
    schema = PasswordValidator().min_length(3).max_length(5)
    assert not await schema.validate("ab")
    assert await schema.validate("abc")
    assert await schema.validate("abcd")
    assert await schema.validate("abcde")
    assert not await schema.validate("abcdef")


@pytest.mark.asyncio
async def test_password_validator_no_otp_like_suffix() -> None:
    """Test password validator for no OTP-like suffix."""
    schema = PasswordValidator().not_otp_like_suffix()
    assert not await schema.validate("abc123456")
    assert await schema.validate("abc12345")
    assert await schema.validate("abc1a23456")


@pytest.mark.asyncio
async def test_password_validator_chained_rules() -> None:
    """Test password validator with chained rules."""
    schema = (
        PasswordValidator()
        .min_letters_count(2)
        .min_digits_count(2)
        .min_length(5)
        .max_length(10)
    )
    assert await schema.validate("abc12")
    assert not await schema.validate("abc")
    assert not await schema.validate("12345")
    assert not await schema.validate("abc123456789")
