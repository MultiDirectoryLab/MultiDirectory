"""Kerberos password sync.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import os

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.policies.password_policy import post_save_password_actions
from ldap_protocol.utils.queries import get_base_directories
from models import User
from security import get_password_hash

_LOCK_FILE = ".lock"
_PATH = "/var/spool/krb5-sync"


async def read_and_save_krb_pwds(session: AsyncSession) -> None:
    """Process file queue with lock.

    :param AsyncSession session: db
    """
    files = [
        fp
        for f in os.listdir(_PATH)
        if os.path.isfile(fp := os.path.join(_PATH, f)) and f != _LOCK_FILE
    ][:100]

    if not files:
        return

    logger.info("found: {}", files)

    domains = await get_base_directories(session)
    if not domains:
        return

    domain = domains[0].name

    for path in files:
        with open(path) as file:
            data = file.read().split("\n")
            username, password = data[0], data[3]

        upn = f"{username}@{domain}"
        query = select(User).where(User.user_principal_name == upn)
        user = await session.scalar(query)

        if not user:
            logger.error("cannot find principal {}", upn)
            os.remove(path)
            continue

        user.password = get_password_hash(password)
        user.password_history.append(password)
        await post_save_password_actions(user, session)
        await session.commit()

        logger.info("synced for {}", upn)
        os.remove(path)
