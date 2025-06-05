"""Security base module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Validate password.

    Args:
        plain_password (str): raw password
        hashed_password (str): pwd hash from db

    Returns:
        bool: is password valid
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash password.

    Args:
        password (str): raw pwd

    Returns:
        str: hash
    """
    return pwd_context.hash(password, max_rounds=9)
