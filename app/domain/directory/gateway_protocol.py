"""Directory Gateway Protocol module."""

from typing import Protocol

from entities import Directory


class DirectoryGatewayProtocol(Protocol):

    async def get_by_dn(self, dn: str) -> Directory | None:
        ...

    async def delete(self, directory: Directory) -> None:
        ...

    async def has_primary_group_members(self, directory_id: int) -> bool:
        ...

    async def commit(self) -> None:
        ...
