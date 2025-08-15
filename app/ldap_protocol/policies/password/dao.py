"""Password Policy DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.utils.helpers import ft_now
from models import Attribute, PasswordPolicy

from .schema import PasswordPolicySchema


class PasswordPolicyDAO:
    """Password Policy DAO."""

    __session: AsyncSession

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        """Initialize Password Policy DAO with a database session."""
        self.__session = session

    async def update_policy(
        self,
        password_policy: PasswordPolicySchema,
    ) -> None:
        """Update Password Policy."""
        await self.__session.execute(
            update(PasswordPolicy).values(
                password_policy.model_dump(mode="json"),
            ),
        )

    async def reset_policy(self) -> "PasswordPolicySchema":
        """Reset (delete) default policy."""
        default_policy = PasswordPolicySchema()
        await self.update_policy(default_policy)
        return default_policy

    async def get_or_create_password_policy(self) -> "PasswordPolicySchema":
        """Get or create password policy."""
        password_policy = await self.__session.scalar(select(PasswordPolicy))

        if not password_policy:
            self.__session.add(
                PasswordPolicy(
                    **PasswordPolicySchema().model_dump(mode="json"),
                ),
            )
            await self.__session.flush()

            password_policy = await self.__session.scalar(
                select(PasswordPolicy),
            )

        return PasswordPolicySchema.model_validate(
            password_policy,
            from_attributes=True,
        )

    async def get_or_create_pwd_last_set(
        self,
        directory_id: int,
    ) -> str | None:
        """Get pwdLastSet."""
        plset_attribute = await self.__session.scalar(
            select(Attribute)
            .where(
                Attribute.directory_id == directory_id,
                Attribute.name == "pwdLastSet",
            ),
        )  # fmt: skip

        if not plset_attribute:
            plset_attribute = Attribute(
                directory_id=directory_id,
                name="pwdLastSet",
                value=ft_now(),
            )

            self.__session.add(plset_attribute)

        return plset_attribute.value
