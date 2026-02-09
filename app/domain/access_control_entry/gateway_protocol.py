"""Gateway Protocol for Access Control Entry."""

from typing import Protocol

from entities import AccessControlEntry
from enums import AceType


class AccessControlEntryGatewayProtocol(Protocol):

    async def get(
        self,
        directory_id: int,
        role_ids: list[int],
        ace_types: list[AceType],
        load_attribute_type: bool = False,
        requeire_attribute_type_null: bool = False,
    ) -> list[AccessControlEntry]:
        ...
