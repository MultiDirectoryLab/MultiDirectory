"""Kerberos update config.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.utils.queries import get_base_directories


async def update_krb5_config(
    kadmin: AbstractKadmin,
    session: AsyncSession,
    settings: Settings,
) -> None:
    """Update kerberos config."""
    # NOTE: wait for kdc to be ready
    for _ in range(30):
        try:
            is_ok = await kadmin.get_status()

            if is_ok:
                break
        except Exception:  # noqa: S112
            continue
        finally:
            await asyncio.sleep(1)

    base_dn_list = await get_base_directories(session)
    base_dn = base_dn_list[0].path_dn
    domain: str = base_dn_list[0].name

    krbadmin = "cn=krbadmin,ou=users," + base_dn
    services_container = "ou=services," + base_dn

    krb5_template = settings.TEMPLATES.get_template("krb5.conf")
    kdc_template = settings.TEMPLATES.get_template("kdc.conf")

    kdc_config = await kdc_template.render_async(domain=domain)

    krb5_config = await krb5_template.render_async(
        domain=domain,
        krbadmin=krbadmin,
        services_container=services_container,
        ldap_uri=settings.KRB5_LDAP_URI,
    )

    await kadmin.setup_configs(krb5_config, kdc_config)
