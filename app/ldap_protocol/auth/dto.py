"""Identity DTO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass


@dataclass
class SetupDTO:
    """Setup DTO."""

    domain: str
    username: str
    user_principal_name: str
    display_name: str
    mail: str
    password: str
