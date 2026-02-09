"""Deletion Validator implementation module."""

from entities import Directory
from ldap_protocol.dialogue import UserSchema

from .deletion_exception import (
    DirectoryHasPrimaryGroupMembersError,
    DomainDirectoryDeletionError,
    SystemDirectoryDeletionError,
    UserSelfDeletionError,
)
from .gateway_protocol import DirectoryGatewayProtocol


class DirectoryDeletionValidator:

    def __init__(self, gateway_protocol: DirectoryGatewayProtocol) -> None:
        self._gateway_protocol = gateway_protocol

    async def validate(self, directory: Directory, user: UserSchema) -> None:
        if directory.is_system:
            raise SystemDirectoryDeletionError()

        if directory.is_domain:
            raise DomainDirectoryDeletionError()

        if directory.is_user and directory.path_dn == user.dn:
            raise UserSelfDeletionError()

        if directory.is_group:
            has_members = await self._gateway_protocol.has_primary_group_members(  # noqa: E501
                directory.id,
            )
            if has_members:
                raise DirectoryHasPrimaryGroupMembersError()
