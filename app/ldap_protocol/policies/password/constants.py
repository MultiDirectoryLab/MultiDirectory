"""Password policy constants file."""

from typing import Literal

type PasswordValidatorLanguageType = Literal["Cyrillic", "Latin"]

MIN_LENGTH_FOR_TRGM: Literal[3] = 3
MAX_BANWORD_LENGTH: Literal[254] = 254

__CYRILLIC_ALPHABET: str = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
CYRILLIC_ALPHABET_SEQUENCE: str = (
    __CYRILLIC_ALPHABET * 2 + __CYRILLIC_ALPHABET[::-1] * 2
)

__LATIN_ALPHABET: str = "abcdefghijklmnopqrstuvwxyz"
LATIN_ALPHABET_SEQUENCE: str = (
    __LATIN_ALPHABET * 2 + __LATIN_ALPHABET[::-1] * 2
)

__BASE_CYRILLIC_KEYBOARD_SEQUENCES: list[str] = [
    "ё!\"№;%:?*()_+",  # noqa: Q003
    "1234567890",
    "0123456789",
    "ё1234567890-=",
    "ё1234567890_+",
    "йцукенгшщзхъ",
    "йцукенгшщзхъ\\",
    "йцукенгшщзхъ|",
    "фывапролджэ",
    "ячсмитьбю.",
    "ячсмитьбю,",
]  # fmt: skip
CYRILLIC_KEYBOARD_SEQUENCES = (
    [v * 2 for v in __BASE_CYRILLIC_KEYBOARD_SEQUENCES] +
    [v[::-1] * 2 for v in __BASE_CYRILLIC_KEYBOARD_SEQUENCES]
)  # fmt: skip

__BASE_LATIN_KEYBOARD_SEQUENCES: list[str] = [
    "~!@#$%^&*()_+",
    "1234567890",
    "0123456789",
    "`1234567890-=",
    "~1234567890_+",
    "qwertyuiop",
    "qwertyuiop[]\\",
    "qwertyuiop{}|",
    "asdfghjkl",
    "asdfghjkl;'",
    "asdfghjkl:\"",  # noqa: Q003
    "zxcvbnm,./",
    "zxcvbnm<>?",
]  # fmt: skip
LATIN_KEYBOARD_SEQUENCES: list[str] = (
    [v * 2 for v in __BASE_LATIN_KEYBOARD_SEQUENCES] +
    [v[::-1] * 2 for v in __BASE_LATIN_KEYBOARD_SEQUENCES]
)  # fmt: skip

REGEXP_DIGITS: str = r"\d"

REGEXP_CYRILLIC_LETTERS: str = r"[а-яА-ЯёЁ]"
REGEXP_LATIN_LETTERS: str = r"[a-zA-Z]"

REGEXP_CYRILLIC_SPECIAL_SYMBOLS: str = r"[^а-яА-ЯёЁ0-9]"
REGEXP_LATIN_SPECIAL_SYMBOLS: str = r"[^a-zA-Z0-9]"

REGEXP_CYRILLIC_UPPERCASE_LETTERS: str = r"[А-ЯЁ]"
REGEXP_LATIN_UPPERCASE_LETTERS: str = r"[A-Z]"

REGEXP_CYRILLIC_LOWERCASE_LETTERS: str = r"[а-яё]"
REGEXP_LATIN_LOWERCASE_LETTERS: str = r"[a-z]"
