"""Auth api/module imports.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from .oauth2 import get_current_user
from .schema import UserSchema

__all__ = ['UserSchema', 'get_current_user']
