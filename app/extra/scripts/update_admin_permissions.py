"""Update web permissions for the admin role.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap_protocol.roles.role_use_case import RoleUseCase


async def update_admin_permissions(role_use_case: RoleUseCase) -> None:
    """Update admin web permissions script."""
    # Implementation of the script goes here
    await role_use_case.update_domain_admins_role_permissions()
