"""Service for checking and updating failed auth attempts.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import time
from datetime import datetime, timezone

from loguru import logger
from sqlalchemy import Integer, delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import Settings
from ldap_protocol.policies.utils import add_lock_and_expire_attributes
from models import Attribute, Directory, User


class AuthLockoutService:
    """Service for checking and updating failed auth attempts."""

    def __init__(self, settings: Settings):
        """Initialize the service.

        :param Settings settings: settings
        """
        self.settings = settings

    async def check_and_update_on_fail(
        self,
        user: User,
        session: AsyncSession,
    ) -> None:
        """Check and update failed auth attempts.

        :param User user: user
        :param AsyncSession session: db session
        :return None:
        """
        now = datetime.now(timezone.utc)
        if (
            user.last_failed_auth
            and (now - user.last_failed_auth).total_seconds()
            > self.settings.AUTH_FAILED_ATTEMPTS_RESET_SEC
        ):
            user.failed_auth_attempts = 1
        else:
            user.failed_auth_attempts += 1
        user.last_failed_auth = now
        logger.info(
            f"AUTH AUDIT: fail for user={user.user_principal_name},"
            + f"failed_auth_attempts={user.failed_auth_attempts}"
        )
        if user.failed_auth_attempts >= self.settings.AUTH_MAX_FAILED_ATTEMPTS:
            await add_lock_and_expire_attributes(
                session, user.directory, self.settings.TIMEZONE
            )

            user.failed_auth_attempts = 0
            user.last_failed_auth = None
            logger.warning(
                f"AUTH AUDIT: user locked out user={user.user_principal_name}"
                + " (LDAP nsAccountLock)"
            )
            await session.commit()
            result = await session.execute(
                select(type(user.directory))
                .where(type(user.directory).id == user.directory.id)
                .options(selectinload(type(user.directory).attributes))
            )
            user.directory = result.scalar_one()

        else:
            await session.commit()

    async def reset_on_success(
        self,
        user: User,
        session: AsyncSession,
    ) -> None:
        """Reset failed auth attempts on success.

        :param User user: user
        :param AsyncSession session: db session
        :return None:
        """
        user.failed_auth_attempts = 0
        user.last_failed_auth = None
        logger.info(f"AUTH AUDIT: success for user={user.user_principal_name}")
        await session.commit()

    def is_locked(self, user: User) -> bool:
        if user.directory and hasattr(user.directory, "attributes"):
            for attr in user.directory.attributes:
                if attr.name == "nsAccountLock" and attr.value == "true":
                    return True
        return False

    async def unlock_expired(self, user: User, session: AsyncSession) -> None:
        """Unlock LDAP lockout for user if expired."""
        attrs = {a.name: a for a in user.directory.attributes}
        if "nsAccountLock" not in attrs or "shadowExpire" not in attrs:
            return

        shadow_expire_attr = next(
            (
                attr
                for attr in user.directory.attributes
                if attr.name == "shadowExpire"
            ),
            None,
        )

        if shadow_expire_attr:
            try:
                expire_timestamp = int(shadow_expire_attr.value) * 86400
                current_timestamp = int(time.time())
                if current_timestamp < expire_timestamp:
                    return
            except (ValueError, TypeError):
                logger.warning(
                    "WARNING: unlock_expired - invalid shadowExpire"
                    + f" format for user={user.user_principal_name}"
                )
                return

            attrs_to_delete = [
                attr
                for attr in user.directory.attributes
                if attr.name in ["nsAccountLock", "shadowExpire"]
            ]
            for attr in attrs_to_delete:
                await session.delete(attr)

        user.failed_auth_attempts = 0
        user.last_failed_auth = None
        logger.info(
            "AUTH AUDIT: unlock expired for user=" + user.user_principal_name
        )
        await session.commit()
        result = await session.execute(
            select(Directory)
            .where(Directory.id == user.directory.id)
            .options(selectinload(Directory.attributes))
        )
        user.directory = result.scalar_one()

    async def unlock_expired_bulk(self, session: AsyncSession) -> None:
        """Mass unlock LDAP lockout for users if expired.

        :param AsyncSession session: db session
        :return None:
        """
        now_days = int(
            datetime.now(tz=self.settings.TIMEZONE).timestamp() // 86400
        )
        expired_dir_ids = (
            await session.scalars(
                select(Attribute.directory_id).where(
                    Attribute.name == "shadowExpire",
                    Attribute.value.isnot(None),
                    Attribute.value.cast(Integer) <= now_days,
                )
            )
        ).all()
        if not expired_dir_ids:
            return

        await session.execute(
            delete(Attribute).where(
                Attribute.directory_id.in_(expired_dir_ids),
                Attribute.name.in_(["nsAccountLock", "shadowExpire"]),
            )
        )
        await session.execute(
            update(User)
            .where(User.directory_id.in_(expired_dir_ids))
            .values(failed_auth_attempts=0, last_failed_auth=None)
        )
        await session.commit()
