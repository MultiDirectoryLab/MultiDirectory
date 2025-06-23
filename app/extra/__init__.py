"""Extra data actions.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .common_passwords_data import COMMON_PASSWORDS
from .dev_data import DATA, TEST_DATA
from .password_ban_words_data import PASSWORD_BAN_WORDS
from .setup_dev import setup_enviroment

__all__ = [
    "COMMON_PASSWORDS",
    "PASSWORD_BAN_WORDS",
    "DATA",
    "TEST_DATA",
    "setup_enviroment",
]
