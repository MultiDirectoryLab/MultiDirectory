"""Dev data creation.

DC=multifactor
  OU=IT
    CN=User 1
    CN=User 2
  CN=Users
    CN=User 3
    CN=User 4
  OU="2FA"
    CN=Service Accounts
      CN=User 5

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Network
from itertools import chain

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.helpers import create_object_sid, generate_domain_sid
from ldap_protocol.utils.queries import get_domain_object_class
from models import (
    Attribute,
    Directory,
    Group,
    NetworkPolicy,
    User,
    directory_table,
    queryable_attr as qa,
)
from password_manager import PasswordValidator


async def _get_group(name: str, session: AsyncSession) -> Group:
    retval = await session.scalars(
        select(Group)
        .join(qa(Group.directory))
        .filter(
            directory_table.c.name == name,
            directory_table.c.object_class == "group",
        ),
    )
    return retval.one()


async def _create_dir(
    data: dict,
    session: AsyncSession,
    domain: Directory,
    password_validator: PasswordValidator,
    parent: Directory | None = None,
) -> None:
    """Create data recursively."""
    dir_ = Directory(
        object_class=data["object_class"],
        name=data["name"],
        parent=parent,
    )
    dir_.groups = []
    dir_.create_path(parent, dir_.get_dn_prefix())

    session.add(dir_)
    await session.flush()
    await session.refresh(dir_, ["id"])

    session.add(
        Attribute(
            name=dir_.rdname,
            value=dir_.name,
            directory_id=dir_.id,
        ),
    )

    dir_.object_sid = create_object_sid(
        domain,
        rid=data.get("objectSid", dir_.id),
        reserved="objectSid" in data,
    )

    if dir_.object_class == "group":
        group = Group(directory_id=dir_.id)
        session.add(group)
        for group_name in data.get("groups", []):
            parent_group: Group = await _get_group(group_name, session)
            dir_.groups.append(parent_group)

        await session.flush()

    if "attributes" in data:
        attrs = chain(
            data["attributes"].items(),
            [("objectClass", [dir_.object_class])],
        )

        for name, values in attrs:
            for value in values:
                session.add(
                    Attribute(
                        directory_id=dir_.id,
                        name=name,
                        value=value if isinstance(value, str) else None,
                        bvalue=value if isinstance(value, bytes) else None,
                    ),
                )

    if "organizationalPerson" in data:
        user_data = data["organizationalPerson"]
        user = User(
            directory_id=dir_.id,
            sam_account_name=user_data["sam_account_name"],
            user_principal_name=user_data["user_principal_name"],
            display_name=user_data["display_name"],
            mail=user_data["mail"],
            password=password_validator.get_password_hash(
                user_data["password"],
            ),
        )
        session.add(user)
        await session.flush()
        session.add(
            Attribute(
                directory_id=dir_.id,
                name="homeDirectory",
                value=f"/home/{user.uid}",
            ),
        )

        for group_name in user_data.get("groups", []):
            parent_group = await _get_group(group_name, session)
            dir_.groups.append(parent_group)

    await session.flush()

    object_class_dao = ObjectClassDAO(session)
    entity_type_dao = EntityTypeDAO(session, object_class_dao)
    await session.refresh(
        instance=dir_,
        attribute_names=["attributes"],
        with_for_update=None,
    )
    await entity_type_dao.attach_entity_type_to_directory(
        directory=dir_,
        is_system_entity_type=True,
    )
    await session.flush()

    if "children" in data:
        for n_data in data["children"]:
            await _create_dir(
                n_data,
                session,
                domain,
                password_validator,
                dir_,
            )


async def setup_enviroment(
    session: AsyncSession,
    *,
    data: list,
    password_validator: PasswordValidator,
    dn: str = "multifactor.dev",
) -> None:
    """Create directories and users for enviroment."""
    cat_result = await session.execute(select(Directory))
    if cat_result.scalar_one_or_none():
        logger.warning("dev data already set up")
        return

    domain = Directory(
        name=dn,
        object_class="domain",
    )
    domain.object_sid = generate_domain_sid()
    domain.path = [f"dc={path}" for path in reversed(dn.split("."))]
    domain.depth = len(domain.path)
    domain.rdname = ""

    async with session.begin_nested():
        session.add(domain)
        session.add(
            NetworkPolicy(
                name="Default open policy",
                netmasks=[IPv4Network("0.0.0.0/0")],
                raw=["0.0.0.0/0"],
                priority=1,
            ),
        )
        await session.flush()
        await session.refresh(domain, ["id"])
        session.add_all(list(get_domain_object_class(domain)))
        await session.flush()

        object_class_dao = ObjectClassDAO(session)
        entity_type_dao = EntityTypeDAO(session, object_class_dao)
        await session.refresh(
            instance=domain,
            attribute_names=["attributes"],
            with_for_update=None,
        )
        await entity_type_dao.attach_entity_type_to_directory(
            directory=domain,
            is_system_entity_type=True,
        )
        await session.flush()

    try:
        for unit in data:
            await _create_dir(
                unit,
                session,
                domain,
                password_validator,
                domain,
            )
    except Exception:
        import traceback

        logger.error(traceback.format_exc())
        raise
