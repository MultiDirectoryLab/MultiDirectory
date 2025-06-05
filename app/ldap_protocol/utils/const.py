"""Functions for SQL.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re
from typing import Annotated

from pydantic import AfterValidator

from .helpers import validate_entry


def _type_validate_entry(entry: str) -> str:
    """Description.

    Args:
        entry (str): entry name

    Returns:
        str: entry name

    Raises:
        ValueError: Invalid entry name
    """
    if validate_entry(entry):
        return entry
    raise ValueError(f"Invalid entry name {entry}")


EMAIL_RE = re.compile(
    r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z0-9-]{2,})+",
)


def _type_validate_email(email: str) -> str:
    """Description.

    Args:
        email (str): email address

    Returns:
        str: email address

    Raises:
        ValueError: Invalid email
    """
    if EMAIL_RE.fullmatch(email):
        return email
    raise ValueError(f"Invalid email {email}")


ENTRY_TYPE = Annotated[str, AfterValidator(_type_validate_entry)]
EmailStr = Annotated[str, AfterValidator(_type_validate_email)]
