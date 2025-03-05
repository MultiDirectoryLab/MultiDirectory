"""empty message.

Revision ID: 275222846605
Revises: 692ae64e0cc5
Create Date: 2025-03-05 12:19:03.407487

"""

import sqlalchemy as sa
from alembic import op
from ldap3.protocol.rfc4512 import AttributeTypeInfo, ObjectClassInfo
from sqlalchemy.orm import Session

from extra.scripts.parse_ldap_txt_schema import (
    get_attribute_type_infos_from_txt_definition,
    get_object_class_infos_from_txt_definition,
)
from models import AttributeType, ObjectClass

# revision identifiers, used by Alembic.
revision = "275222846605"
down_revision = "692ae64e0cc5"
branch_labels = None
depends_on = None


def _get_attribute_types(
    session: Session,
    names: list[str],
) -> list[AttributeType]:
    return (
        session.query(AttributeType)
        .filter(AttributeType.name.in_(names))
        .all()
    )


def _list_to_string(data: list[str]) -> str | None:
    res = None
    if data:
        if len(data) == 1:
            res = data[0]
        else:
            raise ValueError("Data is not a single element list")
    return res


def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    op.create_table(
        "AttributeTypes",
        sa.Column("oid", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("syntax", sa.String(), nullable=False),
        sa.Column("single_value", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("oid"),
        sa.PrimaryKeyConstraint("name"),
    )

    op.create_table(
        "ObjectClasses",
        sa.Column("oid", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("superior", sa.String(), nullable=True),
        sa.Column(
            "kind",
            sa.Enum("AUXILIARY", "STRUCTURAL", "ABSTRACT", native_enum=False),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("oid"),
        sa.PrimaryKeyConstraint("name"),
    )

    op.create_table(
        "ObjectClassAttributeTypeMayMemberships",
        sa.Column("attribute_type_name", sa.String(), nullable=False),
        sa.Column("object_class_name", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["attribute_type_name"],
            ["AttributeTypes.name"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["object_class_name"], ["ObjectClasses.name"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("attribute_type_name", "object_class_name"),
    )
    op.create_unique_constraint(
        "object_class_may_attribute_type_uc",
        "ObjectClassAttributeTypeMayMemberships",
        ["attribute_type_name", "object_class_name"],
    )

    op.create_table(
        "ObjectClassAttributeTypeMustMemberships",
        sa.Column("attribute_type_name", sa.String(), nullable=False),
        sa.Column("object_class_name", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["attribute_type_name"],
            ["AttributeTypes.name"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["object_class_name"], ["ObjectClasses.name"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("attribute_type_name", "object_class_name"),
    )
    op.create_unique_constraint(
        "object_class_must_attribute_type_uc",
        "ObjectClassAttributeTypeMustMemberships",
        ["attribute_type_name", "object_class_name"],
    )

    attribute_type_info: AttributeTypeInfo
    attribute_type_infos = get_attribute_type_infos_from_txt_definition()
    for attribute_type_info in attribute_type_infos.values():
        attribute_type = AttributeType(
            oid=attribute_type_info.oid,
            name=_list_to_string(attribute_type_info.name),
            syntax=attribute_type_info.syntax,
            single_value=attribute_type_info.single_value,
        )
        session.add(attribute_type)
    session.commit()

    object_class_info: ObjectClassInfo
    object_class_infos = get_object_class_infos_from_txt_definition()
    for object_class_info in object_class_infos.values():
        object_class = ObjectClass(
            oid=object_class_info.oid,
            name=_list_to_string(object_class_info.name),
            superior=_list_to_string(object_class_info.superior),
            kind=object_class_info.kind,
        )
        object_class.attribute_types_must.extend(
            _get_attribute_types(session, object_class_info.must_contain)
        )
        object_class.attribute_types_may.extend(
            _get_attribute_types(session, object_class_info.may_contain)
        )
        session.add(object_class)
    session.commit()


def downgrade() -> None:
    """Downgrade."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(
        "object_class_must_attribute_type_uc",
        "ObjectClassAttributeTypeMustMemberships",
        type_="unique",
    )
    op.drop_table("ObjectClassAttributeTypeMustMemberships")

    op.drop_constraint(
        "object_class_may_attribute_type_uc",
        "ObjectClassAttributeTypeMayMemberships",
        type_="unique",
    )
    op.drop_table("ObjectClassAttributeTypeMayMemberships")

    op.drop_table("ObjectClasses")
    op.drop_table("AttributeTypes")
    # ### end Alembic commands ###
