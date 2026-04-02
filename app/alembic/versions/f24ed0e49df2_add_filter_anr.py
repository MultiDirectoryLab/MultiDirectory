"""Extend SearchRequest: add aNR filter.

Revision ID: f24ed0e49df2
Revises: 6303f5c706ec
Create Date: 2025-11-11 08:33:46.685338

"""

import json

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer, Scope
from ldap3.protocol.schemas.ad2012R2 import ad_2012_r2_schema
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import Session

from extra.alembic_utils import temporary_stub_column
from ldap_protocol.ldap_schema._legacy.attribute_type.attribute_type_use_case import (  # noqa: E501
    AttributeTypeUseCaseLegacy,
)
from ldap_protocol.ldap_schema.raw_definition_parser import (
    RawDefinitionParser as RDParser,
)

# revision identifiers, used by Alembic.
revision: None | str = "f24ed0e49df2"
down_revision: None | str = "6303f5c706ec"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


_DEFAULT_ANR_ATTRIBUTE_TYPE_NAMES = (
    "displayName",
    "sAMAccountName",
    "mail",
    "givenName",
    "sn",
    "name",
    "cn",
    "physicalDeliveryOfficeName",
    "proxyAddresses",
)

ad_2012_r2_schema_json = json.loads(ad_2012_r2_schema)


@temporary_stub_column("AttributeTypes", "system_flags", sa.Integer())
def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    op.add_column(
        "AttributeTypes",
        sa.Column("is_included_anr", sa.Boolean(), nullable=True),
    )

    async def _false_all_is_included_anr(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            attribute_type_use_case = await cnt.get(AttributeTypeUseCaseLegacy)

        await attribute_type_use_case.false_all_is_included_anr()
        await session.flush()

    op.run_async(_false_all_is_included_anr)

    op.alter_column("AttributeTypes", "is_included_anr", nullable=False)

    op.alter_column(
        "EntityTypes",
        "object_class_names",
        existing_type=postgresql.ARRAY(sa.VARCHAR()),
        nullable=True,
    )

    async def _ensure_anr_attributes_exist(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            attribute_type_use_case = await cnt.get(AttributeTypeUseCaseLegacy)

        existing_attr_types = (
            await attribute_type_use_case.get_all_raw_by_names(
                list(_DEFAULT_ANR_ATTRIBUTE_TYPE_NAMES),
            )
        )
        existing_names = {attr_type.name for attr_type in existing_attr_types}
        missing_names = set(_DEFAULT_ANR_ATTRIBUTE_TYPE_NAMES) - existing_names
        if not missing_names:
            return

        for raw_definition in ad_2012_r2_schema_json["raw"]["attributeTypes"]:
            attribute_type_dto = RDParser.collect_attribute_type_dto_from_raw(
                raw_definition,
            )
            if attribute_type_dto.name not in missing_names:
                continue

            await attribute_type_use_case.create(attribute_type_dto)
            missing_names.remove(attribute_type_dto.name)
            if not missing_names:
                break

        await session.flush()

    op.run_async(_ensure_anr_attributes_exist)

    async def _mark_anr_included(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            attribute_type_use_case = await cnt.get(AttributeTypeUseCaseLegacy)

        await attribute_type_use_case.mark_anr_included_by_attr_names(
            _DEFAULT_ANR_ATTRIBUTE_TYPE_NAMES,
        )

        await session.flush()

    op.run_async(_mark_anr_included)

    session.commit()


def downgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Downgrade."""
    op.alter_column(
        "EntityTypes",
        "object_class_names",
        existing_type=postgresql.ARRAY(sa.VARCHAR()),
        nullable=False,
    )
    op.drop_column("AttributeTypes", "is_included_anr")
