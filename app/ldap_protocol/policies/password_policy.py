"""Password policies tools and CRUD.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re
from datetime import datetime
from itertools import islice
from typing import Iterable
from zoneinfo import ZoneInfo

from password_validator import PasswordValidator
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import Integer, String, cast, exists, select, update
from sqlalchemy.ext.asyncio import AsyncSession

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


class PasswordPolicySchema(BaseModel):
    """Password Policy schema."""

    name: str = Field(
        "Default domain password policy",
        min_length=3,
        max_length=255,
    )
    password_history_length: int = Field(4, ge=0, le=24)
    maximum_password_age_days: int = Field(0, ge=0, le=999)
    minimum_password_age_days: int = Field(0, ge=0, le=999)
    minimum_password_length: int = Field(7, ge=0, le=256)

    def history_password_hashes(self, user: User) -> Iterable:
        return islice(
            reversed(user.password_history),
            self.password_history_length,
        )

    @model_validator(mode="after")
    def _validate_minimum_pwd_age(self) -> "PasswordPolicySchema":
        if self.minimum_password_age_days > self.maximum_password_age_days:
            raise ValueError(
                "Minimum password age days must be "
                "lower or equal than maximum password age days",
            )
        return self

    # async def create_policy_settings(self, session: AsyncSession) -> Self:
    #     """Create policies settings.

    #     :param AsyncSession session: db session
    #     :return PasswordPolicySchema: password policy.
    #     """
    #     existing_policy = await session.scalar(select(exists(PasswordPolicy)))
    #     if existing_policy:
    #         raise PermissionError("Policy already exists")
    #     session.add(PasswordPolicy(**self.model_dump(mode="json")))
    #     await session.flush()
    #     return self

    # @classmethod
    # async def get_ensure_password_policy(
    #     cls,
    #     session: AsyncSession,
    # ) -> "PasswordPolicySchema":
    #     """Get ensure password policy.

    #     :param AsyncSession session: db
    #     :return PasswordPolicySchema: policy
    #     """
    #     password_policy = await session.scalar(select(PasswordPolicy))
    #     if not password_policy:
    #         return await cls().create_policy_settings(session)
    #     return cls.model_validate(password_policy, from_attributes=True)

    # async def update_password_policy(self, session: AsyncSession) -> None:
    #     """Update password policy.

    #     :param AsyncSession session: db
    #     """
    #     await session.execute(
    #         (update(PasswordPolicy).values(self.model_dump(mode="json"))),
    #     )
    #     await session.commit()

    # FIXME: why is it "delete"? its update
    # @classmethod
    # async def delete_password_policy(
    #     cls,
    #     session: AsyncSession,
    # ) -> "PasswordPolicySchema":
    #     """Reset (delete) default policy.

    #     :param AsyncSession session: db
    #     :return PasswordPolicySchema: schema policy
    #     """
    #     default_policy = cls()
    #     await default_policy.update_password_policy(session)
    #     return default_policy

    # @staticmethod
    # async def get_ensure_pwd_last_set(
    #     session: AsyncSession,
    #     directory_id: int,
    # ) -> Attribute:
    #     """Get pwdLastSet.

    #     :param AsyncSession session: db
    #     :param int directory_id: id
    #     :return Attribute: pwdLastSet
    #     """
    #     plset = await session.scalar(
    #         select(Attribute)
    #         .where(
    #             Attribute.directory_id == directory_id,
    #             Attribute.name == "pwdLastSet",
    #         ),
    #     )  # fmt: skip
    #     if not plset:
    #         plset = Attribute(
    #             directory_id=directory_id,
    #             name="pwdLastSet",
    #             value=ft_now(),
    #         )

    #         session.add(plset)
    #         await session.commit()

    #     return plset

    # @staticmethod
    # def _count_password_age_days(last_pwd_set: Attribute) -> int:
    #     """Get number of days, pwd exists.

    #     :param Attribute last_pwd_set: pwdLastSet
    #     :return int: days
    #     """
    #     tz = ZoneInfo("UTC")
    #     now = datetime.now(tz=tz)

    #     val = (
    #         ft_to_dt(int(last_pwd_set.value)).astimezone(tz)
    #         if last_pwd_set and last_pwd_set.value is not None
    #         else now
    #     )

    #     return (now - val).days

    # def validate_min_age(self, last_pwd_set: Attribute) -> bool:
    #     """Validate min password change age.

    #     :param Attribute last_pwd_set: last pwd set
    #     :return bool: can change pwd
    #         True - not valid, can not change
    #         False - valid, can change

    #         on minimum_password_age_days can always change.
    #     """
    #     if self.minimum_password_age_days == 0:
    #         return False

    #     password_age_days = self._count_password_age_days(last_pwd_set)

    #     return password_age_days < self.minimum_password_age_days

    # def validate_max_age(self, last_pwd_set: Attribute) -> bool:
    #     """Validate max password change age.

    #     :param Attribute last_pwd_set: last pwd set
    #     :return bool: is pwd expired
    #         True - not valid, expired
    #         False - valid, not expired

    #         on maximum_password_age_days always valid.
    #     """
    #     if self.maximum_password_age_days == 0:
    #         return False

    #     password_age_days = self._count_password_age_days(last_pwd_set)

    #     return password_age_days > self.maximum_password_age_days

    # async def _get_md_password_validator(self) -> "MdPasswordValidator":
    #     return MdPasswordValidator.from_password_policy(self)

    # async def validate_password_with_policy(
    #     self,
    #     password: str,
    #     user: User | None,
    # ) -> list[str]:
    #     """Validate password with chosen policy.

    #     :param str password: new raw password
    #     :param User user: db user
    #     :return list[str]: errors
    #     """
    #     errors: list[str] = []
    #     history_password_hashes: Iterable = []

    #     if user is not None:
    #         history_password_hashes = islice(
    #             reversed(user.password_history),
    #             self.password_history_length,
    #         )

    #     for password_hash in history_password_hashes:
    #         if verify_password(password, password_hash):
    #             errors.append("password history violation")
    #             break

    #     if len(password) <= self.minimum_password_length:
    #         errors.append("password minimum length violation")

    #     regexp = (
    #         re.search("[A-ZА-Я]", password) is None,
    #         re.search("[a-zа-я]", password) is None,
    #         re.search("[0-9]", password) is None,
    #         password.lower() in _COMMON_PASSWORDS,
    #     )

    #     if any(regexp):
    #         errors.append("password complexity violation")

    #     if password[-6:].isdecimal():
    #         errors.append("password cannot end with 6 digits")

    #     return errors


class PasswordPolicyDAO:
    """Password Policy DAO."""

    _session: AsyncSession

    def __init__(self, session: AsyncSession):
        """Initialize Password Policy DAO with a database session."""
        self._session = session

    async def update_password_policy(
        self,
        password_policy: PasswordPolicySchema,
    ) -> None:
        """Update Password Policy."""
        await self._session.execute(
            (  # FIXME тут скобки лишние?
                update(PasswordPolicy).values(
                    password_policy.model_dump(mode="json")
                )
            ),
        )
        await self._session.commit()

    # FIXME: why is it "delete"? its update
    async def delete_password_policy(self) -> "PasswordPolicySchema":
        """Reset (delete) default policy."""
        default_policy = PasswordPolicySchema()
        await self.update_password_policy(default_policy)
        return default_policy

    async def create_policy_settings(
        self,
        pwd_schema: PasswordPolicySchema,
    ) -> "PasswordPolicySchema":
        """Create policies settings."""
        existing_policy = await self._session.scalar(
            select(exists(PasswordPolicy))
        )
        if existing_policy:
            raise PermissionError("Policy already exists")
        self._session.add(PasswordPolicy(**pwd_schema.model_dump(mode="json")))
        await self._session.flush()
        return pwd_schema

    async def get_ensure_password_policy(self) -> "PasswordPolicySchema":
        """Get ensure password policy."""
        password_policy = await self._session.scalar(select(PasswordPolicy))
        if not password_policy:
            pwd_schema = PasswordPolicySchema()
            return await self.create_policy_settings(pwd_schema)
        return PasswordPolicySchema.model_validate(
            password_policy,
            from_attributes=True,
        )

    async def get_ensure_pwd_last_set(
        self,
        directory_id: int,
    ) -> Attribute:
        """Get pwdLastSet."""
        plset_attribute = await self._session.scalar(
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

            self._session.add(plset_attribute)
            await self._session.commit()

        return plset_attribute

    @staticmethod
    def _count_password_age_days(last_pwd_set: Attribute) -> int:
        """Get number of days, pwd exists."""
        tz = ZoneInfo("UTC")
        now = datetime.now(tz=tz)

        val = (
            ft_to_dt(int(last_pwd_set.value)).astimezone(tz)
            if last_pwd_set and last_pwd_set.value is not None
            else now
        )

        return (now - val).days

    def validate_min_age(
        self,
        password_policy: PasswordPolicySchema,
        last_pwd_set: Attribute,
    ) -> bool:
        """Validate min password change age."""
        if password_policy.minimum_password_age_days == 0:
            return False

        password_age_days = self._count_password_age_days(last_pwd_set)

        return password_age_days < password_policy.minimum_password_age_days

    def validate_max_age(
        self,
        password_policy: PasswordPolicySchema,
        last_pwd_set: Attribute,
    ) -> bool:
        """Validate max password change age."""
        if password_policy.maximum_password_age_days == 0:
            return False

        password_age_days = self._count_password_age_days(last_pwd_set)

        return password_age_days > password_policy.maximum_password_age_days

    async def validate_password_with_policy(
        self,
        password_policy: PasswordPolicySchema,
        password: str,
        user: User | None,
    ) -> list[str]:
        """Validate password with chosen policy.

        :param str password: new raw password
        :param User user: db user
        :return list[str]: errors
        """
        errors: list[str] = []

        # 1
        if user:
            for password_hash in password_policy.history_password_hashes(user):
                if verify_password(password, password_hash):
                    errors.append("password history violation")
                    break

        # 2
        if len(password) <= password_policy.minimum_password_length:
            errors.append("password minimum length violation")

        # 3, 4, 5, 6
        regexp = (
            re.search("[A-ZА-Я]", password) is None,
            re.search("[a-zа-я]", password) is None,
            re.search("[0-9]", password) is None,
            password.lower() in _COMMON_PASSWORDS,
        )
        if any(regexp):
            errors.append("password complexity violation")

        # 7
        if password[-6:].isdecimal():
            errors.append("password cannot end with 6 digits")

        return errors


# class PasswordValidatorSettings(BaseModel):
#     """PasswordValidatorSettings."""

#     password_history_length: int
#     maximum_password_age_days: int
#     minimum_password_age_days: int
#     minimum_password_length: int


class MdPasswordValidator(PasswordValidator):
    """MdPasswordValidator."""


#     _settings: PasswordValidatorSettings
#     _user: User
#     _password: str

#     def __init__(
#         self,
#         password_policy: PasswordPolicySchema | PasswordPolicy,
#         user: User,
#         password: str,
#     ):
#         """Init."""
#         super().__init__()
#         self._settings = PasswordValidatorSettings(
#             password_history_length=password_policy.password_history_length,
#             maximum_password_age_days=password_policy.maximum_password_age_days,
#             minimum_password_age_days=password_policy.minimum_password_age_days,
#             minimum_password_length=password_policy.minimum_password_length,
#         )
#         self._user = user
#         self._password = password

#     def validate(self, pwd: str) -> bool:
#         """Validate password."""
#         return True
