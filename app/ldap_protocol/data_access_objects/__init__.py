"""Common Password DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .password_ban_word_dao import (
    PasswordBanWordDAO,
    PasswordBanWordPaginationSchema,
    PasswordBanWordSchema,
)

__all__ = [
    "PasswordBanWordDAO",
    "PasswordBanWordPaginationSchema",
    "PasswordBanWordSchema",
]
