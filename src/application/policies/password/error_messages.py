"""Error Messages for password validator checks.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class ErrorMessages:
    """Error messages for password validation checks."""

    LONGER = "Password must be longer"

    NOT_OLD_ENOUGH = "Password is not old enough to update"
    NOT_IN_HISTORY = "Password must not be in history"
    NOT_LIKE_OTP = "Password suffix should not be similar to OTP"

    UNAUTHORIZED_LANGUAGE = "Password must not contain characters from an unauthorized language"  # fmt: skip # noqa: E501

    MORE_LOWERCASE_LETTERS = "Password must contain more lowercase letters"
    MORE_UPPERCASE_LETTERS = "Password must contain more uppercase letters"

    MORE_LETTERS = "Password must contain more letters"
    MORE_DIGITS = "Password must contain more digits"

    SHORTER = "Password should be shorter"

    MORE_UNIQUE_SYMBOLS = "Password must contain more unique symbols"
    MORE_SPECIAL_SYMBOLS = "Password must contain more special symbols"

    FEWER_ALPHABET_LETTERS = "Password must contain fewer consecutive alphabet letters"  # fmt: skip # noqa: E501
    FEWER_KEYBOARD_CHARACTERS = "Password must contain fewer consecutive keyboard characters"  # fmt: skip # noqa: E501
    FEWER_REPEATING_CHARACTERS = "Password must contain fewer consecutive repeating characters"  # fmt: skip # noqa: E501

    NOT_EQUAL_BAN_WORD = "Password must not equal ban word"
    NOT_CONTAIN_BAN_WORD = "Password must not contain ban word"
