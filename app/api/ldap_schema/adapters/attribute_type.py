"""Attribute Type management routers.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.base_adapter import BaseAdapter
from ldap_protocol.ldap_schema.attribute_type_dao import (
    AttributeTypeDAO,
    AttributeTypeSchema,
)


class AttributeTypeFastAPIAdapter(BaseAdapter[AttributeTypeDAO]):
    """Attribute Type management routers."""

    _DEFAULT_ATTRIBUTE_TYPE_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.15"
    _DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD = False
    _DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM = False
    _exceptions_map: dict[type[Exception], int] = {
        IntegrityError: status.HTTP_409_CONFLICT,
    }

    def __init__(
        self,
        service: AttributeTypeDAO,
        session: AsyncSession,
        dao: AttributeTypeDAO,
    ) -> None:
        """Initialize dependencies via DI.

        :param AttributeTypeDAO service: Attribute Type DAO.
        :param AsyncSession session: Database session.
        :param AttributeTypeDAO dao: Attribute Type DAO.
        """
        super().__init__(service)
        self._session = session
        self._dao = dao

    async def create_one(self, request_data: AttributeTypeSchema) -> None:
        """Create a new Attribute Type.

        :param AttributeTypeSchema request_data: Data for creating Attribute Type.
        :return None.
        """
        try:
            await self._dao.create_one(
                oid=request_data.oid,
                name=request_data.name,
                syntax=self._DEFAULT_ATTRIBUTE_TYPE_SYNTAX,
                single_value=request_data.single_value,
                no_user_modification=self._DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD,
                is_system=self._DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM,
            )
            await self._session.commit()
        except IntegrityError:
            raise
