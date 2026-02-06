"""Password Validator Settings.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal

from .constants import (
    CYRILLIC_ALPHABET_SEQUENCE,
    CYRILLIC_KEYBOARD_SEQUENCES,
    LATIN_ALPHABET_SEQUENCE,
    LATIN_KEYBOARD_SEQUENCES,
    REGEXP_CYRILLIC_LETTERS,
    REGEXP_CYRILLIC_LOWERCASE_LETTERS,
    REGEXP_CYRILLIC_SPECIAL_SYMBOLS,
    REGEXP_CYRILLIC_UPPERCASE_LETTERS,
    REGEXP_DIGITS,
    REGEXP_LATIN_LETTERS,
    REGEXP_LATIN_LOWERCASE_LETTERS,
    REGEXP_LATIN_SPECIAL_SYMBOLS,
    REGEXP_LATIN_UPPERCASE_LETTERS,
    PasswordValidatorLanguageType,
)


class PasswordValidatorSettings:
    """Password Validator Settings."""

    __language: PasswordValidatorLanguageType

    otp_tail_size: Literal[6] = 6
    alphabet_sequence: str
    keyboard_sequences: list[str]
    regexp_letters: str
    regexp_digits: str = REGEXP_DIGITS
    regexp_not_valid_letters: str
    regexp_special_symbols: str
    regexp_uppercase_letters: str
    regexp_lowercase_letters: str

    def setup_language(
        self,
        language: PasswordValidatorLanguageType,
    ) -> None:
        """Set instance language params."""
        if language in ("Cyrillic", "Latin"):
            self.__language = language
        else:
            raise ValueError(
                f"PasswordValidatorSettings: Unsupported language `{language}`. "  # noqa: E501
                "Supported languages: Cyrillic, Latin.",
            )

        if self.__language == "Cyrillic":
            self.alphabet_sequence = CYRILLIC_ALPHABET_SEQUENCE
            self.keyboard_sequences = CYRILLIC_KEYBOARD_SEQUENCES
            self.regexp_letters = REGEXP_CYRILLIC_LETTERS
            self.regexp_not_valid_letters = REGEXP_LATIN_LETTERS
            self.regexp_special_symbols = REGEXP_CYRILLIC_SPECIAL_SYMBOLS
            self.regexp_uppercase_letters = REGEXP_CYRILLIC_UPPERCASE_LETTERS
            self.regexp_lowercase_letters = REGEXP_CYRILLIC_LOWERCASE_LETTERS

        elif self.__language == "Latin":
            self.alphabet_sequence = LATIN_ALPHABET_SEQUENCE
            self.keyboard_sequences = LATIN_KEYBOARD_SEQUENCES
            self.regexp_letters = REGEXP_LATIN_LETTERS
            self.regexp_not_valid_letters = REGEXP_CYRILLIC_LETTERS
            self.regexp_special_symbols = REGEXP_LATIN_SPECIAL_SYMBOLS
            self.regexp_uppercase_letters = REGEXP_LATIN_UPPERCASE_LETTERS
            self.regexp_lowercase_letters = REGEXP_LATIN_LOWERCASE_LETTERS
