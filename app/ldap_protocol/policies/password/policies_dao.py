"""Password Policy DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import asdict

from adaptix import P
from adaptix.conversion import allow_unlinked_optional, get_converter
from sqlalchemy import Integer, String, cast, exists, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from abstract_dao import AbstractDAO
from ldap_protocol.policies.password.exceptions import (
    PasswordPolicyAlreadyExistsError,
    PasswordPolicyNotFoundError,
)
from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.helpers import ft_now
from models import Attribute, PasswordPolicy, User

from .dataclasses import PasswordPolicyDTO

_convert_model_to_dto = get_converter(PasswordPolicy, PasswordPolicyDTO)
_convert_dto_to_model = get_converter(
    PasswordPolicyDTO,
    PasswordPolicy,
    recipe=[
        allow_unlinked_optional(P[PasswordPolicy].id),
    ],
)


class PasswordPolicyDAO(AbstractDAO[PasswordPolicyDTO]):
    """Password Policy DAO."""

    _session: AsyncSession

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        """Initialize Password Policy DAO with a database session."""
        self._session = session

    async def get_all(self) -> list[PasswordPolicyDTO]:
        """Get all password policies."""
        policies = await self._session.scalars(select(PasswordPolicy))
        return [_convert_model_to_dto(policy) for policy in policies]

    async def get(self, _id: int) -> PasswordPolicyDTO:
        """Get password policy by ID."""
        policy = await self._session.scalar(select(PasswordPolicy))

        if not policy:
            raise PasswordPolicyNotFoundError("Policy not found")

        return _convert_model_to_dto(policy)

    async def create(
        self,
        dto: PasswordPolicyDTO,
    ) -> None:
        """Create a new password policy."""
        existing_policy = await self._session.scalar(
            select(exists(PasswordPolicy)),
        )
        if existing_policy:
            raise PasswordPolicyAlreadyExistsError("Policy already exists")

        destination = _convert_dto_to_model(dto)
        self._session.add(destination)
        await self._session.flush()

    async def update(
        self,
        _id: int,
        dto: PasswordPolicyDTO,
    ) -> None:
        """Update policy."""
        await self._session.execute(
            update(PasswordPolicy).values(asdict(dto)),
        )
        await self._session.commit()

    async def delete(self, _id: int) -> None:
        """Delete (reset) default policy."""
        await self.update(_id, self.get_default_policy())

    @staticmethod
    def get_default_policy() -> PasswordPolicyDTO:
        """Get default password policy."""
        return PasswordPolicyDTO(
            name="Default domain password policy",
            password_history_length=4,
            maximum_password_age_days=0,
            minimum_password_age_days=0,
            minimum_password_length=7,
            password_must_meet_complexity_requirements=True,
        )

    async def get_or_create_pwd_last_set(
        self,
        directory_id: int,
    ) -> str | None:
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

        return plset_attribute.value

    async def post_save_password_actions(
        self,
        user: User,
    ) -> None:
        """Post save actions for password update.

        :param User user: user from db
        :param AsyncSession session: db
        """
        await self._session.execute(  # update bind reject attribute
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
                directory_id=user.directory_id,
                name="userAccountControl",
            )
        )
        await self._session.execute(query)

        user.password_history.append(user.password)
        await self._session.flush()
