from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from models import User


class AuthLockoutService:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def check_and_update_on_fail(
        self,
        user: User,
        session: AsyncSession,
    ) -> None:
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
        if user.failed_auth_attempts >= self.settings.AUTH_MAX_FAILED_ATTEMPTS:
            user.lockout_until = now + timedelta(
                seconds=self.settings.AUTH_LOCKOUT_DURATION_SEC
            )
        await session.commit()

    async def reset_on_success(
        self,
        user: User,
        session: AsyncSession,
    ) -> None:
        user.failed_auth_attempts = 0
        user.last_failed_auth = None
        user.lockout_until = None
        await session.commit()

    def is_locked(self, user: User) -> bool:
        now = datetime.now(timezone.utc)
        return user.lockout_until is not None and user.lockout_until > now

    async def unlock_expired(self, user: User, session: AsyncSession) -> None:
        now = datetime.now(timezone.utc)
        if user.lockout_until and user.lockout_until <= now:
            user.lockout_until = None
            user.failed_auth_attempts = 0
            await session.commit()
