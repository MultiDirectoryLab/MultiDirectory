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

from itertools import chain

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ldap_protocol.utils.helpers import create_object_sid, generate_domain_sid
from ldap_protocol.utils.queries import get_domain_object_class
from models import (
    Attribute,
    CatalogueSetting,
    Directory,
    DirectoryMembership,
    Group,
    NetworkPolicy,
    PolicyProtocol,
    User,
)
from security import get_password_hash


async def _get_group(name: str, session: AsyncSession) -> Group:
    retval = await session.scalars(
        select(Group)
        .join(Group.directory)
        .filter(
            Directory.name == name,
            Directory.object_class == "group",
        ),
    )
    return retval.one()


async def _create_dir(
    data: dict,
    session: AsyncSession,
    domain: Directory,
    parent: Directory | None = None,
) -> None:
    """Create data recursively."""
    dir_ = Directory(
        object_class=data["object_class"],
        name=data["name"],
        parent=parent,
    )
    dir_.create_path(parent, dir_.get_dn_prefix())

    async with session.begin_nested():
        session.add(dir_)
        session.add(
            Attribute(
                name=dir_.rdname,
                value=dir_.name,
                directory=dir_,
            ),
        )
        await session.flush()

    dir_.object_sid = create_object_sid(
        domain,
        rid=data.get("objectSid", dir_.id),
        reserved="objectSid" in data,
    )

    if dir_.object_class == "group":
        group = Group(directory=dir_)
        session.add(group)
        for group_name in data.get("groups", []):
            parent_group: Group = await _get_group(group_name, session)
            session.add(
                DirectoryMembership(
                    group_id=parent_group.id,
                    directory_id=dir_.id,
                ),
            )

    if "attributes" in data:
        attrs = chain(
            data["attributes"].items(),
            [("objectClass", [dir_.object_class])],
        )

        for name, values in attrs:
            for value in values:
                session.add(
                    Attribute(
                        directory=dir_,
                        name=name,
                        value=value if isinstance(value, str) else None,
                        bvalue=value if isinstance(value, bytes) else None,
                    ),
                )

    if "organizationalPerson" in data:
        user_data = data["organizationalPerson"]
        user = User(
            directory=dir_,
            sam_accout_name=user_data["sam_accout_name"],
            user_principal_name=user_data["user_principal_name"],
            display_name=user_data["display_name"],
            mail=user_data["mail"],
            password=get_password_hash(user_data["password"]),
        )
        session.add(user)
        await session.flush()
        session.add(
            Attribute(
                directory=dir_,
                name="homeDirectory",
                value=f"/home/{user.uid}",
            ),
        )

        for group_name in user_data.get("groups", []):
            parent_group = await _get_group(group_name, session)
            await session.flush()
            session.add(
                DirectoryMembership(
                    group_id=parent_group.id,
                    directory_id=dir_.id,
                ),
            )

    await session.flush()

    if "children" in data:
        for n_data in data["children"]:
            await _create_dir(n_data, session, domain, dir_)


async def setup_enviroment(
    session: AsyncSession, *, data: list, dn: str = "multifactor.dev",
) -> None:
    """Create directories and users for enviroment."""
    cat_result = await session.execute(
        select(CatalogueSetting).filter(
            CatalogueSetting.name == "defaultNamingContext",
        ),
    )
    if cat_result.scalar():
        logger.warning("dev data already set up")
        return

    domain = Directory(
        name=dn,
        object_class="domain",
        object_sid=generate_domain_sid(),
    )
    domain.path = [f"dc={path}" for path in reversed(dn.split("."))]
    domain.depth = len(domain.path)
    domain.rdname = ''

    async with session.begin_nested():
        session.add(domain)
        session.add(
            NetworkPolicy(
                name="Default open policy",
                netmasks=["0.0.0.0/0"],
                raw=["0.0.0.0/0"],
                priority=1,
                protocols=[PolicyProtocol.WebAdminAPI, PolicyProtocol.LDAP],
            ),
        )
        session.add_all(list(get_domain_object_class(domain)))
        await session.flush()

    try:
        for unit in data:
            await _create_dir(unit, session, domain, domain)
    except Exception:
        import traceback

        logger.error(traceback.format_exc())  # noqa
        raise
