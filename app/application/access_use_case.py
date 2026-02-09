"""Access Use Case module."""

from domain.access_control_entry.gateway_protocol import (
    AccessControlEntryGatewayProtocol,
)

from entities import AccessControlEntry, Directory
from enums import AceType
from ldap_protocol.dialogue import UserSchema


class AccessControlUseCase:

    def __init__(
        self,
        access_control_entry_gateway: AccessControlEntryGatewayProtocol,  # интерфейс  # noqa: E501
    ) -> None:
        self._access_control_entry_gateway = access_control_entry_gateway

    async def can_delete(
        self,
        directory: Directory,
        user: UserSchema,
    ) -> bool:
        if not user.role_ids:
            return False

        aces = await self._access_control_entry_gateway.get(
            directory_id=directory.id,
            role_ids=user.role_ids,
            ace_types=[AceType.DELETE],
            load_attribute_type=True,
        )
        return self._can_delete(aces, directory.entity_type_id)

    @staticmethod
    def _can_delete(
        aces: list[AccessControlEntry],
        entity_type_id: int | None,
    ) -> bool:
        for ace in aces:
            if (
                ace.entity_type_id is None
                or ace.entity_type_id == entity_type_id
            ):
                return bool(ace.is_allow)

        return False
