"""Domain/Directory gw for handle requests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Protocol

from entities import Directory


class DomainReadProtocol(Protocol):
    """RootDSE gw."""

    async def get_domain(self) -> Directory: ...
