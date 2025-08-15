"""Password policies tools and CRUD.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime
from typing import Self
from zoneinfo import ZoneInfo

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import exists, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.utils.helpers import ft_now, ft_to_dt
from models import Attribute, PasswordPolicy


class PasswordPolicySchema(BaseModel):
    """PasswordPolicy schema."""

    name: str = Field(
        "Default domain password policy",
        min_length=3,
        max_length=255,
    )
    history_length: int = Field(4, ge=0, le=24)
    max_age_days: int = Field(0, ge=0, le=999)
    min_age_days: int = Field(0, ge=0, le=999)
    min_length: int = Field(7, ge=0, le=256)
    password_must_meet_complexity_requirements: bool = True

    @model_validator(mode="after")
    def _validate_minimum_pwd_age(self) -> "PasswordPolicySchema":
        if self.min_age_days > self.max_age_days:
            raise ValueError(
                "Minimum password age days must be "
                "lower or equal than maximum password age days",
            )
        return self

    async def create_policy_settings(self, session: AsyncSession) -> Self:
        """Create policies settings.

        :param AsyncSession session: db session
        :return PasswordPolicySchema: password policy.
        """
        existing_policy = await session.scalar(select(exists(PasswordPolicy)))
        if existing_policy:
            raise PermissionError("Policy already exists")
        session.add(PasswordPolicy(**self.model_dump(mode="json")))
        await session.flush()
        return self

    @classmethod
    async def get_policy_settings(
        cls,
        session: AsyncSession,
    ) -> "PasswordPolicySchema":
        """Get policy settings.

        :param AsyncSession session: db
        :return PasswordPolicySchema: policy
        """
        policy = await session.scalar(select(PasswordPolicy))
        if not policy:
            return await cls().create_policy_settings(session)
        return cls.model_validate(policy, from_attributes=True)

    async def update_policy_settings(self, session: AsyncSession) -> None:
        """Update policy.

        :param AsyncSession session: db
        """
        await session.execute(
            (update(PasswordPolicy).values(self.model_dump(mode="json"))),
        )
        await session.commit()

    @classmethod
    async def delete_policy_settings(
        cls,
        session: AsyncSession,
    ) -> "PasswordPolicySchema":
        """Reset (delete) default policy.

        :param AsyncSession session: db
        :return PasswordPolicySchema: schema policy
        """
        default_policy = cls()
        await default_policy.update_policy_settings(session)
        return default_policy

    @staticmethod
    def _count_password_exists_days(last_pwd_set: Attribute) -> int:
        """Get number of days, pwd exists.

        :param Attribute last_pwd_set: pwdLastSet
        :return int: days
        """
        tz = ZoneInfo("UTC")
        now = datetime.now(tz=tz)

        val = (
            ft_to_dt(int(last_pwd_set.value)).astimezone(tz)
            if last_pwd_set and last_pwd_set.value is not None
            else now
        )

        return (now - val).days

    @staticmethod
    async def get_pwd_last_set(
        session: AsyncSession,
        directory_id: int,
    ) -> Attribute:
        """Get pwdLastSet.

        :param AsyncSession session: db
        :param int directory_id: id
        :return Attribute: pwdLastSet
        """
        plset = await session.scalar(
            select(Attribute)
            .where(
                Attribute.directory_id == directory_id,
                Attribute.name == "pwdLastSet",
            ),
        )  # fmt: skip
        if not plset:
            plset = Attribute(
                directory_id=directory_id,
                name="pwdLastSet",
                value=ft_now(),
            )

            session.add(plset)
            await session.commit()

        return plset
