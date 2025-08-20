"""Password Policy DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import asdict

from adaptix.conversion import get_converter
from sqlalchemy import exists, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from abstract_dao import AbstractDAO
from api.password_policy.schemas import PasswordPolicySchema
from ldap_protocol.policies.password.exceptions import (
    PasswordPolicyAlreadyExistsError,
)
from ldap_protocol.utils.helpers import ft_now
from models import Attribute, PasswordPolicy

from .dataclasses import PasswordPolicyDTO

_convert = get_converter(PasswordPolicy, PasswordPolicyDTO)


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
        return [_convert(policy) for policy in policies]

    async def get(self) -> PasswordPolicyDTO:  # type: ignore[override]
        """Get password policy by ID."""
        policy = await self._session.scalar(select(PasswordPolicy))

        if not policy:
            policy_dto = PasswordPolicyDTO(
                **PasswordPolicySchema().model_dump(),
            )
            await self.create(policy_dto)
            policy = await self._session.scalar(select(PasswordPolicy))

        return _convert(policy)  # type: ignore

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

        destination = PasswordPolicy(**asdict(dto))
        self._session.add(destination)
        await self._session.flush()

    async def update(  # type: ignore[override]
        self,
        dto: PasswordPolicyDTO,
    ) -> None:
        """Update policy."""
        await self._session.execute(
            update(PasswordPolicy).values(asdict(dto)),
        )
        await self._session.commit()

    async def delete(self) -> None:  # type: ignore[override]
        """Delete (reset) default policy."""
        await self.update(self.get_default_policy())

    @staticmethod
    def get_default_policy() -> PasswordPolicyDTO:
        """Get default password policy."""
        return PasswordPolicyDTO(**PasswordPolicySchema().model_dump())

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
