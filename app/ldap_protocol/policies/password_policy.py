"""Password policies tools and CRUD.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime
from itertools import islice
from typing import Self
from zoneinfo import ZoneInfo

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import Integer, String, cast, exists, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.helpers import ft_now, ft_to_dt
from models import Attribute, PasswordPolicy, User
from password_manager import PasswordValidator, count_password_age_days


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
        self, directory_id: int,
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


class PasswordPolicyUseCases:
    """Password Policy Use Cases."""

    def __init__(
        self,
        password_policy_dao: PasswordPolicyDAO,
        validator: PasswordValidator,
    ) -> None:
        """Initialize Password Policy Use Cases."""
        self.password_policy_dao = password_policy_dao
        self.validator = validator

    async def get_or_create_pwd_last_set(
        self,
        directory_id: int,
    ) -> str | None:
        """Get pwdLastSet."""
        return await self.password_policy_dao.get_or_create_pwd_last_set(
            directory_id,
        )

    async def get_or_create_password_policy(self) -> "PasswordPolicySchema":
        """Get or create password policy."""
        return await self.password_policy_dao.get_or_create_password_policy()

    async def update_policy(
        self,
        password_policy: PasswordPolicySchema,
    ) -> None:
        """Update Password Policy."""
        await self.password_policy_dao.update_policy(password_policy)

    async def reset_policy(self) -> "PasswordPolicySchema":
        """Reset (delete) default policy."""
        return await self.password_policy_dao.reset_policy()

    @staticmethod
    async def post_save_password_actions(
        user: User,
        session: AsyncSession,
    ) -> None:
        """Post save actions for password update.

        :param User user: user from db
        :param AsyncSession session: db
        """
        await session.execute(  # update bind reject attribute
            update(Attribute)
            .values({"value": ft_now()})
            .filter_by(directory_id=user.directory_id, name="pwdLastSet"),
        )

        new_value = cast(
            cast(Attribute.value, Integer).op("&")(
                ~UserAccountControlFlag.PASSWORD_EXPIRED,
            ),
            String,
        )
        query = (
            update(Attribute)
            .values(value=new_value)
            .filter_by(
                directory_id=user.directory_id, name="userAccountControl",
            )
        )
        await session.execute(query)

        user.password_history.append(user.password)
        await session.flush()

    async def check_expired_max_age(
        self,
        password_policy: PasswordPolicySchema,
        user: User | None = None,
    ) -> bool:
        """Validate max password change age."""
        if password_policy.max_age_days == 0:
            return False

        if not user:
            return True

        pwd_last_set = (
            await self.password_policy_dao.get_or_create_pwd_last_set(
                user.directory_id,
            )
        )
        password_age_days = count_password_age_days(pwd_last_set)

        return password_age_days > password_policy.max_age_days

    async def check_password_violations(
        self,
        password: str,
        user: User | None = None,
    ) -> list[str]:
        """Validate password with chosen policy.

        :param PasswordPolicySchema password_policy: Password Policy
        :param str password: new raw password
        :return list[str]: error messages
        """
        password_policy = (
            await self.password_policy_dao.get_or_create_password_policy()
        )

        self.validator.not_otp_like_suffix()

        if user and password_policy.history_length:
            history = islice(
                reversed(user.password_history),
                password_policy.history_length,
            )

            self.validator.reuse_prevention(
                password_history=history,
            )

        if user and password_policy.min_age_days:
            pwd_last_set = (
                await self.password_policy_dao.get_or_create_pwd_last_set(
                    user.directory_id,
                )
            )
            self.validator.min_age(
                password_policy.min_age_days,
                pwd_last_set,
            )

        if password_policy.min_length:
            self.validator.min_length(password_policy.min_length)

        if password_policy.password_must_meet_complexity_requirements:
            self.validator.min_complexity()

        await self.validator.validate(password)
        return self.validator.error_messages
