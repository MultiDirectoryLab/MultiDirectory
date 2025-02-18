"""Password policies tools and CRUD.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re
from datetime import datetime
from itertools import islice
from typing import Iterable, Self
from zoneinfo import ZoneInfo

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import Integer, String, cast, exists, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.helpers import ft_now, ft_to_dt
from models import Attribute, PasswordPolicy, User
from security import verify_password

with open("extra/common_pwds.txt") as f:
    _COMMON_PASSWORDS = set(f.read().split("\n"))


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
    qeury = (
        update(Attribute)
        .values(value=new_value)
        .filter_by(directory_id=user.directory_id, name="userAccountControl")
    )
    await session.execute(qeury)

    user.password_history.append(user.password)
    await session.flush()


class PasswordPolicySchema(BaseModel):
    """PasswordPolicy schema."""

    name: str = Field(
        "Default domain password policy",
        min_length=3,
        max_length=255,
    )
    password_history_length: int = Field(4, ge=0, le=24)
    maximum_password_age_days: int = Field(0, ge=0, le=999)
    minimum_password_age_days: int = Field(0, ge=0, le=999)
    minimum_password_length: int = Field(7, ge=0, le=256)
    password_must_meet_complexity_requirements: bool = True

    @model_validator(mode="after")
    def _validate_minimum_pwd_age(self) -> "PasswordPolicySchema":
        if self.minimum_password_age_days > self.maximum_password_age_days:
            raise ValueError(
                "Minimum password age days must be "
                "lower or equal than maximum password age days",
            )
        return self

    async def create_policy_settings(
        self,
        session: AsyncSession,
        kadmin: AbstractKadmin,
    ) -> Self:
        """Create policies settings.

        :param AsyncSession session: db session
        :return PasswordPolicySchema: password policy.
        """
        existing_policy = await session.scalar(select(exists(PasswordPolicy)))
        if existing_policy:
            raise PermissionError("Policy already exists")
        session.add(PasswordPolicy(**self.model_dump(mode="json")))
        await session.flush()
        await kadmin.create_or_update_policy(
            self.minimum_password_age_days,
            self.maximum_password_age_days,
            self.minimum_password_length,
            3 if self.password_must_meet_complexity_requirements else 0,
        )
        return self

    @classmethod
    async def get_policy_settings(
        cls,
        session: AsyncSession,
        kadmin: AbstractKadmin,
    ) -> "PasswordPolicySchema":
        """Get policy settings.

        :param AsyncSession session: db
        :return PasswordPolicySchema: policy
        """
        policy = await session.scalar(select(PasswordPolicy))
        if not policy:
            return await cls().create_policy_settings(session, kadmin)
        return cls.model_validate(policy, from_attributes=True)

    async def update_policy_settings(
        self,
        session: AsyncSession,
        kadmin: AbstractKadmin,
    ) -> None:
        """Update policy.

        :param AsyncSession session: db
        """
        await session.execute(
            (update(PasswordPolicy).values(self.model_dump(mode="json"))),
        )
        await kadmin.create_or_update_policy(
            self.minimum_password_age_days,
            self.maximum_password_age_days,
            self.minimum_password_length,
            3 if self.password_must_meet_complexity_requirements else 0,
        )
        await session.commit()

    @classmethod
    async def delete_policy_settings(
        cls,
        session: AsyncSession,
        kadmin: AbstractKadmin,
    ) -> "PasswordPolicySchema":
        """Reset (delete) default policy.

        :param AsyncSession session: db
        :return PasswordPolicySchema: schema policy
        """
        default_policy = cls()
        await default_policy.update_policy_settings(session, kadmin)
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
            select(Attribute).where(
                Attribute.directory_id == directory_id,
                Attribute.name == "pwdLastSet",
            ),
        )
        if not plset:
            plset = Attribute(
                directory_id=directory_id,
                name="pwdLastSet",
                value=ft_now(),
            )

            session.add(plset)
            await session.commit()

        return plset

    def validate_min_age(self, last_pwd_set: Attribute) -> bool:
        """Validate min password change age.

        :param Attribute last_pwd_set: last pwd set
        :return bool: can change pwd
            True - not valid, can not change
            False - valid, can change

            on minimum_password_age_days can always change.
        """
        if self.minimum_password_age_days == 0:
            return False

        password_exists = self._count_password_exists_days(last_pwd_set)

        return password_exists < self.minimum_password_age_days

    def validate_max_age(self, last_pwd_set: Attribute) -> bool:
        """Validate max password change age.

        :param Attribute last_pwd_set: last pwd set
        :return bool: is pwd expired
            True - not valid, expired
            False - valid, not expired

            on maximum_password_age_days always valid.
        """
        if self.maximum_password_age_days == 0:
            return False

        password_exists = self._count_password_exists_days(last_pwd_set)

        return password_exists > self.maximum_password_age_days

    async def validate_password_with_policy(
        self,
        password: str,
        user: User | None,
    ) -> list[str]:
        """Validate password with chosen policy.

        :param str password: new raw password
        :param User user: db user
        :param AsyncSession session: db
        :return bool: status
        """
        errors = []
        history: Iterable = []

        if user is not None:
            history = islice(
                reversed(user.password_history),
                self.password_history_length,
            )

        for pwd_hash in history:
            if verify_password(password, pwd_hash):
                errors.append("password history violation")
                break

        if len(password) <= self.minimum_password_length:
            errors.append("password minimum length violation")

        regex = (
            re.search("[A-ZА-Я]", password) is not None,
            re.search("[a-zа-я]", password) is not None,
            re.search("[0-9]", password) is not None,
            password.lower() not in _COMMON_PASSWORDS,
        )

        if self.password_must_meet_complexity_requirements and not all(regex):
            errors.append("password complexity violation")

        if password[-6:].isdecimal():
            errors.append("password cannot end with 6 digits")

        return errors
