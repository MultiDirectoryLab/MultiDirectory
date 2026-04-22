"""Kerberos configuration update script.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pathlib import Path

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.kerberos.utils import get_system_container_dn
from ldap_protocol.utils.queries import get_base_directories

KRB5_CONF_PATH = Path("/etc/krb5kdc/krb5.conf")
KDC_CONF_PATH = Path("/etc/krb5kdc/kdc.conf")
STASH_FILE_PATH = Path("/etc/krb5kdc/krb5.d/stash.keyfile")


def _migrate_legacy_dns(content: str) -> str:
    """Replace legacy DN formats with current ones.

    :param content: File content to migrate.
    :return: Migrated content.
    """
    return content.replace("ou=services", "ou=System").replace("ou=users", "cn=users")


async def update_krb5_config(session: AsyncSession, settings: Settings) -> None:
    """Update Kerberos configuration files via direct write to shared volume.

    Renders krb5.conf and kdc.conf from templates and writes them directly
    to the shared volume. Also migrates legacy DN formats in stash.keyfile
    if present (ou=services -> ou=System, ou=users -> cn=users).

    :param session: Database session for fetching base directories.
    :param settings: Application settings with template environment.
    :raises Exception: If config rendering or writing fails.
    """
    if not KRB5_CONF_PATH.parent.exists():
        logger.error(f"Config directory {KRB5_CONF_PATH.parent} not found, kerberos volume not mounted")
        return

    base_dn_list = await get_base_directories(session)
    if not base_dn_list:
        logger.warning("No base directories found")
        return

    base_dn = base_dn_list[0].path_dn
    domain = base_dn_list[0].name
    krbadmin = f"cn=krbadmin,cn=users,{base_dn}"
    services_container = get_system_container_dn(base_dn)

    krb5_config = await settings.TEMPLATES.get_template("krb5.conf").render_async(
        domain=domain,
        krbadmin=krbadmin,
        services_container=services_container,
        ldap_uri=settings.KRB5_LDAP_URI,
        mfa_push_url=settings.KRB5_MFA_PUSH_URL,
        sync_password_url=settings.KRB5_SYNC_PASSWORD_URL,
    )
    kdc_config = await settings.TEMPLATES.get_template("kdc.conf").render_async(domain=domain)

    KRB5_CONF_PATH.write_text(krb5_config, encoding="utf-8")
    KDC_CONF_PATH.write_text(kdc_config, encoding="utf-8")

    if STASH_FILE_PATH.exists():
        stash_content = STASH_FILE_PATH.read_text(encoding="utf-8")
        if "ou=services" in stash_content or "ou=users" in stash_content:
            STASH_FILE_PATH.write_text(_migrate_legacy_dns(stash_content), encoding="utf-8")
