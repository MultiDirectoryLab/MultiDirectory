"""Password policy routers.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .password_ban_word_router import password_ban_word_router
from .password_policy_router import password_policy_router
from .user_password_history_router import user_password_history_router

__all__ = [
    "password_ban_word_router",
    "password_policy_router",
    "user_password_history_router",
]
