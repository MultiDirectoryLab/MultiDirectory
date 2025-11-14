"""Identity use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Network
from itertools import chain

from loguru import logger
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from entities import (
    Attribute,
    Directory,
    Group,
    NetworkPolicy,
    User,
    UserApiPermissions,
)
from enums import ApiPermissionsType
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.utils.helpers import create_object_sid, generate_domain_sid
from ldap_protocol.utils.queries import get_domain_object_class
from password_manager import PasswordValidator
from repo.pg.tables import queryable_attr as qa


class SetupGateway:
    """Setup use case."""

    def __init__(
        self,
        session: AsyncSession,
        password_validator: PasswordValidator,
        entity_type_dao: EntityTypeDAO,
    ) -> None:
        """Initialize Setup use case.

        :param session: SQLAlchemy AsyncSession

        return: None.
        """
        self._session = session
        self._password_validator = password_validator
        self._entity_type_dao = entity_type_dao

    async def is_setup(self) -> bool:
        """Check if setup is performed.

        :return: bool (True if setup is performed, False otherwise)
        """
        query = select(
            exists(Directory).where(qa(Directory.parent_id).is_(None)),
        )
        retval = await self._session.scalars(query)
        return retval.one()

    async def setup_enviroment(
        self,
        *,
        data: list,
        username: str,
        dn: str = "multifactor.dev",
    ) -> None:
        """Create directories and users for enviroment."""
        cat_result = await self._session.execute(select(Directory))
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

        async with self._session.begin_nested():
            self._session.add(domain)
            self._session.add(
                NetworkPolicy(
                    name="Default open policy",
                    netmasks=[IPv4Network("0.0.0.0/0")],
                    raw=["0.0.0.0/0"],
                    priority=1,
                ),
            )
            await self._session.flush()
            await self._session.refresh(domain, ["id"])
            self._session.add_all(list(get_domain_object_class(domain)))
            await self._session.flush()

            await self._session.refresh(
                instance=domain,
                attribute_names=["attributes"],
                with_for_update=None,
            )
            await self._entity_type_dao.attach_entity_type_to_directory(
                directory=domain,
                is_system_entity_type=True,
            )
            await self._session.flush()

        try:
            for unit in data:
                await self.create_dir(
                    unit,
                    domain,
                    domain,
                )
            await self.create_api_permissions(username)

        except Exception:
            import traceback

            logger.error(traceback.format_exc())
            raise

    async def create_dir(
        self,
        data: dict,
        domain: Directory,
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

        self._session.add(dir_)
        await self._session.flush()
        await self._session.refresh(dir_, ["id"])

        self._session.add(
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
            self._session.add(group)
            for group_name in data.get("groups", []):
                parent_group = await self._get_group(group_name)
                dir_.groups.append(parent_group)

            await self._session.flush()

        if "attributes" in data:
            attrs = chain(
                data["attributes"].items(),
                [("objectClass", [dir_.object_class])],
            )

            for name, values in attrs:
                for value in values:
                    self._session.add(
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
                password=self._password_validator.get_password_hash(
                    user_data["password"],
                ),
            )
            self._session.add(user)
            await self._session.flush()
            self._session.add(
                Attribute(
                    directory_id=dir_.id,
                    name="homeDirectory",
                    value=f"/home/{user.uid}",
                ),
            )

            for group_name in user_data.get("groups", []):
                parent_group = await self._get_group(group_name)
                dir_.groups.append(parent_group)

        await self._session.flush()

        await self._session.refresh(
            instance=dir_,
            attribute_names=["attributes"],
            with_for_update=None,
        )
        await self._entity_type_dao.attach_entity_type_to_directory(
            directory=dir_,
            is_system_entity_type=True,
        )
        await self._session.flush()

        if "children" in data:
            for n_data in data["children"]:
                await self.create_dir(
                    n_data,
                    domain,
                    dir_,
                )

    async def _get_group(self, name: str) -> Group:
        """Get group by name.

        :param str name: group name
        :return Group: group
        """
        retval = await self._session.scalars(
            select(Group)
            .join(qa(Group.directory))
            .filter(
                qa(Directory.name) == name,
                qa(Directory.object_class) == "group",
            ),
        )
        return retval.one()

    async def create_api_permissions(self, username: str) -> None:
        user_id = await self._session.scalar(
            select(qa(User.id))
            .where(qa(User.sam_account_name) == username),
        )  # fmt: skip

        if user_id:
            self._session.add(
                UserApiPermissions(
                    user_id=user_id,
                    permissions=[perm for perm in ApiPermissionsType],
                ),
            )
            await self._session.flush()
