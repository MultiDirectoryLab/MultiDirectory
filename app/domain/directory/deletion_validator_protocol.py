"""Deletion Validator Protocol module."""

from typing import Protocol

from entities import Directory, User


class DirectoryDeletionValidatorProtocol(Protocol):

    async def validate(self, directory: Directory, user: User) -> None:
        ...
