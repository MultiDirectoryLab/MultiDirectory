"""Add domain controller.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from constants import DOMAIN_CONTROLLERS_OU_NAME
from entities import Attribute, Directory
from enums import SamAccountTypeCodes, SecurityPrincipalRid
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import (
    EntityTypeUseCase,
)
from ldap_protocol.objects import UserAccountControlFlag
from ldap_protocol.rid_manager import ObjectSIDUseCase
from ldap_protocol.roles.role_use_case import RoleUseCase
from repo.pg.tables import queryable_attr as qa


async def _add_domain_controller(
    session: AsyncSession,
    role_use_case: RoleUseCase,
    entity_type_use_case: EntityTypeUseCase,
    settings: Settings,
    dc_ou_dir: Directory,
    object_sid_use_case: ObjectSIDUseCase,
) -> None:
    dc_directory = Directory(
        object_class="",
        name=settings.HOST_MACHINE_SHORT_NAME,
        is_system=True,
    )
    dc_directory.create_path(dc_ou_dir)
    session.add(dc_directory)
    await session.flush()

    dc_directory.parent_id = dc_ou_dir.id
    await object_sid_use_case.add(
        directory=dc_directory,
        rid=SecurityPrincipalRid.DOMAIN_CONTROLLERS,
    )
    await session.flush()

    attributes = [
        Attribute(
            name="objectClass",
            value="top",
            directory_id=dc_directory.id,
        ),
        Attribute(
            name="objectClass",
            value="computer",
            directory_id=dc_directory.id,
        ),
        Attribute(
            name="sAMAccountName",
            value=settings.HOST_MACHINE_SHORT_NAME,
            directory_id=dc_directory.id,
        ),
        Attribute(
            name="userAccountControl",
            value=str(
                UserAccountControlFlag.SERVER_TRUST_ACCOUNT,
            ),
            directory_id=dc_directory.id,
        ),
        Attribute(
            name="sAMAccountType",
            value=str(SamAccountTypeCodes.SAM_MACHINE_ACCOUNT),
            directory_id=dc_directory.id,
        ),
        Attribute(
            name="ipHostNumber",
            value=settings.DEFAULT_NAMESERVER,
            directory_id=dc_directory.id,
        ),
        Attribute(
            name="cn",
            value=settings.HOST_MACHINE_SHORT_NAME,
            directory_id=dc_directory.id,
        ),
    ]

    session.add_all(attributes)
    await session.flush()

    await role_use_case.inherit_parent_aces(
        parent_directory=dc_ou_dir,
        directory=dc_directory,
    )
    await entity_type_use_case.attach_entity_type_to_directory(
        directory=dc_directory,
        is_system_entity_type=False,
        object_class_names={"top", "computer"},
    )
    await session.flush()


async def add_domain_controller(
    session: AsyncSession,
    settings: Settings,
    role_use_case: RoleUseCase,
    entity_type_use_case: EntityTypeUseCase,
    object_sid_use_case: ObjectSIDUseCase,
) -> None:
    logger.info("Adding domain controller.")

    domain_controllers_ou = await session.scalar(
        select(Directory).where(
            qa(Directory.name) == DOMAIN_CONTROLLERS_OU_NAME,
        ),
    )

    if not domain_controllers_ou:
        logger.debug("Domain controllers OU does not exist.")
        return

    domain_controller = await session.scalar(
        select(qa(Directory.id).distinct())
        .join(qa(Directory.attributes))
        .where(
            qa(Directory.parent_id) == domain_controllers_ou.id,
            qa(Attribute.name) == "ipHostNumber",
            qa(Attribute.value) == settings.DEFAULT_NAMESERVER,
        ),
    )

    if domain_controller:
        logger.debug("Domain controllers already exists")
        return

    await _add_domain_controller(
        session=session,
        role_use_case=role_use_case,
        entity_type_use_case=entity_type_use_case,
        settings=settings,
        dc_ou_dir=domain_controllers_ou,
        object_sid_use_case=object_sid_use_case,
    )

    logger.debug("Domain controller added.")

    await session.commit()
