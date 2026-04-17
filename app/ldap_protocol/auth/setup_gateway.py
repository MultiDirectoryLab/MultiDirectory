"""Identity use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Network
from itertools import chain

from loguru import logger
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Attribute, Directory, Group, NetworkPolicy, User
from enums import EntityTypeNames
from ldap_protocol.ldap_schema.attribute_value_validator import (
    AttributeValueValidator,
)
from ldap_protocol.ldap_schema.directory_dao import DirectoryDAO
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import (
    EntityTypeUseCase,
)
from ldap_protocol.rid_manager import ObjectSIDUseCase
from ldap_protocol.utils.async_cache import base_directories_cache
from ldap_protocol.utils.queries import get_domain_object_class
from password_utils import PasswordUtils
from repo.pg.tables import queryable_attr as qa


class SetupGateway:
    """Setup use case."""

    def __init__(
        self,
        session: AsyncSession,
        password_utils: PasswordUtils,
        entity_type_use_case: EntityTypeUseCase,
        attribute_value_validator: AttributeValueValidator,
        directory_dao: DirectoryDAO,
        object_sid_use_case: ObjectSIDUseCase,
    ) -> None:
        """Initialize Setup use case.

        :param session: SQLAlchemy AsyncSession

        return: None.
        """
        self._session = session
        self._password_utils = password_utils
        self._entity_type_use_case = entity_type_use_case
        self._attribute_value_validator = attribute_value_validator
        self._directory_dao = directory_dao
        self._object_sid_use_case = object_sid_use_case

    async def is_setup(self) -> bool:
        """Check if setup is performed.

        :return: bool (True if setup is performed, False otherwise)
        """
        query = select(
            exists(Directory)
            .where(qa(Directory.parent_id).is_(None)),
        )  # fmt: skip
        retval = await self._session.scalars(query)
        return retval.one()

    async def setup_enviroment(
        self,
        *,
        data: list,
        is_system: bool = True,
        domain: Directory,
    ) -> None:
        """Create directories and users for enviroment."""
        async with self._session.begin_nested():
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

            entity_type = await self._entity_type_use_case.get(
                EntityTypeNames.DOMAIN,
            )
            await self._directory_dao.bind_entity_type(
                domain,
                entity_type.id if entity_type else None,
            )
            if not self._attribute_value_validator.is_directory_valid(domain):
                raise ValueError(
                    "Invalid directory attribute values during environment setup",  # noqa: E501
                )
            await self._session.flush()

        try:
            for unit in data:
                await self.create_dir(
                    unit,
                    is_system=is_system,
                    domain=domain,
                    parent=domain,
                )
            base_directories_cache.clear()

        except Exception:
            import traceback

            logger.error(traceback.format_exc())
            raise

    async def create_base_domain(
        self,
        dn: str = "multifactor.dev",
    ) -> Directory:
        """Create base domain."""
        domain = Directory(name=dn, object_class="domain")
        domain.is_system = True
        domain.path = [f"dc={path}" for path in reversed(dn.split("."))]
        domain.depth = len(domain.path)
        domain.rdname = ""
        self._session.add(domain)
        await self._session.flush()
        return domain

    async def create_dir(
        self,
        data: dict,
        is_system: bool,
        domain: Directory,
        parent: Directory | None = None,
    ) -> None:
        """Create data recursively."""
        dir_ = Directory(
            is_system=is_system,
            object_class=data["object_class"],
            name=data["name"],
        )
        dir_.groups = []
        dir_.create_path(parent, dir_.get_dn_prefix())

        self._session.add(dir_)
        await self._session.flush()
        dir_.parent_id = parent.id if parent else None
        await self._session.refresh(dir_, ["id"])

        self._session.add(
            Attribute(
                name=dir_.rdname,
                value=dir_.name,
                directory_id=dir_.id,
            ),
        )

        if "objectSid" in data:
            await self._object_sid_use_case.add(
                directory_id=dir_.id,
                rid=int(data["objectSid"]),
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
                password=self._password_utils.get_password_hash(
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
            attribute_names=["attributes", "user"],
            with_for_update=None,
        )

        entity_type = None
        if entity_type_name := data.get("entity_type_name"):
            entity_type = await self._entity_type_use_case.get(
                entity_type_name,
            )
        entity_type_id = entity_type.id if entity_type else None
        await self._entity_type_use_case.attach_entity_type_to_directory(
            directory=dir_,
            is_system_entity_type=True,
            entity_type_id=entity_type_id,
        )
        if not self._attribute_value_validator.is_directory_valid(dir_):
            raise ValueError("Invalid directory attribute values")
        await self._session.flush()

        if "children" in data:
            for n_data in data["children"]:
                await self.create_dir(
                    n_data,
                    is_system=is_system,
                    domain=domain,
                    parent=dir_,
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
