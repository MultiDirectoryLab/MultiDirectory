"""Object SID use case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from enums import SidPrefix
from ldap_protocol.ldap_schema.object_class.object_class_dao import ObjectClassDAO
from ldap_protocol.rid_manager.exceptions import RIDManagerObjectSIDNotFoundError
from ldap_protocol.rid_manager.object_sid_gateway import ObjectSIDGateway
from ldap_protocol.rid_manager.rid_manager_use_case import RIDManagerUseCase
from ldap_protocol.rid_manager.rid_set_use_case import RIDSetUseCase
from ldap_protocol.utils.async_cache import objectsid_allowed_object_classes_cache


class ObjectSIDUseCase:
    """Object SID use case."""

    def __init__(
        self,
        gateway: ObjectSIDGateway,
        rid_set_use_case: RIDSetUseCase,
        session: AsyncSession,
        rid_manager_use_case: RIDManagerUseCase,
        object_class_dao: ObjectClassDAO,
    ) -> None:
        """Initialize Object SID use case."""
        self._gateway = gateway
        self._rid_set_use_case = rid_set_use_case
        self._session = session
        self._rid_manager_use_case = rid_manager_use_case
        self._object_class_dao = object_class_dao

    @objectsid_allowed_object_classes_cache
    async def get_available_object_classes(self) -> set[str]:
        """ObjectClasses that allow objectSid (mustContain/mayContain)."""
        names = await self._object_class_dao.get_object_class_names_include_attribute_type("objectSid")
        return {n.lower() for n in names}

    async def is_objectsid_needed(self, object_class_names: set[str]) -> bool:
        """Check if objectSid is needed for objectClasses."""
        allowed = await self.get_available_object_classes()
        oc_lower = {n.lower() for n in object_class_names}
        return bool(oc_lower & allowed)

    async def ensure_objectsid(
        self, directory_id: int, rid: int | None = None, sid_prefix: SidPrefix = SidPrefix.DOMAIN_IDENTIFIER
    ) -> None:
        """Add objectSid and raise if it still doesn't exist."""
        await self.add(directory_id=directory_id, rid=rid, sid_prefix=sid_prefix)
        await self._session.flush()
        try:
            await self._gateway.get(directory_id)
        except RIDManagerObjectSIDNotFoundError as exc:
            raise RuntimeError("objectSid was not created") from exc

    async def get_domain_identifier(self) -> str:
        """Get domain identifier."""
        return await self._gateway.get_domain_identifier()

    async def add(
        self, directory_id: int, rid: int | None = None, sid_prefix: SidPrefix = SidPrefix.DOMAIN_IDENTIFIER
    ) -> None:
        """Add object SID."""
        if rid is None:
            rid = await self._rid_set_use_case.allocate_next_rid()

        if sid_prefix == SidPrefix.BUILT_IN_DOMAIN:
            object_sid = f"{sid_prefix}-{rid}"
        elif sid_prefix == SidPrefix.DOMAIN_IDENTIFIER:
            domain_identifier = await self._gateway.get_domain_identifier()
            object_sid = f"{sid_prefix}-{domain_identifier}-{rid}"

        await self._gateway.add(directory_id, object_sid)
