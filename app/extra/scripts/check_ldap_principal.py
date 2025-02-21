"""Check ldap principal and keytab existence.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import os

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.kerberos import (
    AbstractKadmin,
    KerberosState,
    get_krb_server_state,
)
from ldap_protocol.utils.queries import get_base_directories


async def check_ldap_principal(
    kadmin: AbstractKadmin, session: AsyncSession, settings: Settings
) -> None:
    """Check ldap principal and keytab existence.

    :param AbstractKadmin kadmin: kadmin
    :param AsyncSession session: db
    :param Settings settings: settings
    """
    logger.info("Checking ldap principal and keytab existence.")

    if os.path.exists(settings.KRB5_LDAP_KEYTAB):
        return

    domains = await get_base_directories(session)
    if not domains:
        logger.info("Cannot get base directory")
        return

    domain = domains[0].name
    ldap_principal_name = f"ldap/{domain}"

    kerberos_state = await get_krb_server_state(session)

    if kerberos_state != KerberosState.READY:
        logger.info("Kerberos server is not ready")
        return

    status = await kadmin.get_status(wait_for_positive=True)

    if status:
        await kadmin.ldap_principal_setup(
            ldap_principal_name, settings.KRB5_LDAP_KEYTAB
        )
