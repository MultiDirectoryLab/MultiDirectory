"""Check ldap principal and keytab existence.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio

import httpx
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.kerberos import (
    AbstractKadmin,
    KerberosState,
    KRBAPIError,
    get_krb_server_state,
)
from ldap_protocol.utils.queries import get_base_directories


async def save_ldap_keytab(
    kadmin: AbstractKadmin,
    settings: Settings,
    ldap_principal_name: str,
) -> None:
    """Save ldap keytab.

    :param AbstractKadmin kadmin: kadmin
    :param Settings settings: settings
    :param str ldap_principal_name: ldap principal name
    """
    try:
        response = await kadmin.ktadd([ldap_principal_name], False)
        with open(settings.KRB5_LDAP_KEYTAB, "wb") as f:
            f.write(response.read())
    except KRBAPIError:
        logger.error("Cannot get keytab for ldap service")


async def check_ldap_principal(
    kadmin: AbstractKadmin,
    session: AsyncSession,
    settings: Settings,
) -> None:
    """Check ldap principal and keytab existence.

    :param AbstractKadmin kadmin: kadmin
    :param AsyncSession session: db
    :param Settings settings: settings
    """
    logger.info("Checking ldap principal and keytab existence.")

    domains = await get_base_directories(session)
    if not domains:
        logger.error("Cannot get base directory")
        return

    domain = domains[0].name
    ldap_principal_name = f"ldap/{domain}"

    kerberos_state = await get_krb_server_state(session)

    if kerberos_state != KerberosState.READY:
        logger.info("Kerberos server is not ready")
        return

    while True:
        try:
            data = await kadmin.get_status()
        except (httpx.ConnectError, httpx.ConnectTimeout):
            await asyncio.sleep(1)
        else:
            if data:
                break
            await asyncio.sleep(1)

    try:
        await kadmin.get_principal(ldap_principal_name)
    except KRBAPIError:
        try:
            await kadmin.add_principal(ldap_principal_name, None)
        except KRBAPIError:
            logger.error("Cannot add principal for ldap service")
            return

    await save_ldap_keytab(kadmin, settings, ldap_principal_name)
