"""Add Contact objectClass and mailRecipient to LDAP schema.

Revision ID: c5a9b3f2e8d7
Revises: 8164b4a9e1f1, f1abf7ef2443
Create Date: 2026-01-19 12:00:00.000000

"""

from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import EntityType, ObjectClass
from enums import EntityTypeNames
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type_use_case import EntityTypeUseCase
from ldap_protocol.utils.queries import get_base_directories
from ldap_protocol.utils.raw_definition_parser import (
    RawDefinitionParser as RDParser,
)
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision = "c5a9b3f2e8d7"
down_revision = ("8164b4a9e1f1", "f1abf7ef2443")
branch_labels: None | str = None
depends_on: None | str = None


def upgrade(container: AsyncContainer) -> None:
    """Add Contact objectClass and mailRecipient to LDAP schema."""

    async def _create_object_classes(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        """Create Contact and mailRecipient object classes."""
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        if not await get_base_directories(session):
            return

        mail_recipient_raw = (
            "( 1.2.840.113556.1.3.46 NAME 'mailRecipient' "
            "SUP top AUXILIARY "
            "MAY (mail $ cn $ displayName $ description) )"
        )

        mail_recipient_info = RDParser.get_object_class_info(
            raw_definition=mail_recipient_raw,
        )
        mail_recipient = await RDParser.create_object_class_by_info(
            session=session,
            object_class_info=mail_recipient_info,
        )
        session.add(mail_recipient)

        contact_raw = (
            "( 1.2.840.113556.1.5.15 NAME 'contact' "
            "SUP organizationalPerson STRUCTURAL "
            "MAY (displayName $ description $ telephoneNumber $ "
            "mail $ mobile $ title $ department $ company $ "
            "facsimileTelephoneNumber $ homePhone $ street $ "
            "postalCode $ l $ st $ co $ c) )"
        )

        contact_info = RDParser.get_object_class_info(
            raw_definition=contact_raw,
        )
        contact = await RDParser.create_object_class_by_info(
            session=session,
            object_class_info=contact_info,
        )
        session.add(contact)

        await session.commit()

    async def _create_entity_type(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        """Create Contact Entity Type."""
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            entity_type_use_case = await cnt.get(EntityTypeUseCase)

        if not await get_base_directories(session):
            return

        await entity_type_use_case.create(
            EntityTypeDTO(
                name=EntityTypeNames.CONTACT,
                object_class_names=[
                    "top",
                    "person",
                    "organizationalPerson",
                    "contact",
                    "mailRecipient",
                ],
                is_system=True,
            ),
        )

        await session.commit()

    op.run_async(_create_object_classes)
    op.run_async(_create_entity_type)


def downgrade(container: AsyncContainer) -> None:
    """Remove Contact objectClass and mailRecipient from LDAP schema."""

    async def _delete_entity_type(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        """Delete Contact Entity Type."""
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        if not await get_base_directories(session):
            return

        await session.execute(
            delete(EntityType).where(
                qa(EntityType.name) == EntityTypeNames.CONTACT,
            ),
        )

        await session.commit()

    async def _delete_object_classes(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        """Delete Contact and mailRecipient object classes."""
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        if not await get_base_directories(session):
            return

        await session.execute(
            delete(ObjectClass).where(
                qa(ObjectClass.name) == "contact",
            ),
        )
        await session.execute(
            delete(ObjectClass).where(
                qa(ObjectClass.name) == "mailRecipient",
            ),
        )

        await session.commit()

    op.run_async(_delete_entity_type)
    op.run_async(_delete_object_classes)
