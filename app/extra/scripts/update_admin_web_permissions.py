"""Update web permissions for the admin role.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Role
from enums import AuthorizationRules
from ldap_protocol.roles.role_use_case import RoleConstants
from repo.pg.tables import queryable_attr as qa


async def update_admin_web_permissions(session: AsyncSession) -> None:
    """Update admin web permissions script."""
    # Implementation of the script goes here
    query = (
        sa.select(Role)
        .where(qa(Role.name) == RoleConstants.DOMAIN_ADMINS_ROLE_NAME)
    )  # fmt: skip
    role = (await session.scalars(query)).one()
    role.web_permissions = AuthorizationRules(sum(AuthorizationRules))
    await session.commit()
