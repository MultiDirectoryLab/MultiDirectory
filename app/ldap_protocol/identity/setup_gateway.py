"""Identity use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Directory
from extra.setup_dev import setup_enviroment
from ldap_protocol.identity.dto import SetupDTO
from ldap_protocol.identity.exceptions.auth import (
    AlreadyConfiguredError,
    ForbiddenError,
)
from ldap_protocol.policies.audit.audit_use_case import AuditUseCase
from ldap_protocol.policies.password import PasswordPolicyUseCases
from ldap_protocol.roles.role_use_case import RoleUseCase
from password_manager import PasswordValidator
from repo.pg.tables import queryable_attr as qa


class SetupGateway:
    """Setup use case."""

    def __init__(
        self,
        session: AsyncSession,
        password_validator: PasswordValidator,
        password_use_cases: PasswordPolicyUseCases,
        role_use_case: RoleUseCase,
        audit_use_case: AuditUseCase,
    ) -> None:
        """Initialize Setup use case.

        :param session: SQLAlchemy AsyncSession

        return: None.
        """
        self._session = session
        self._password_validator = password_validator
        self._password_use_cases = password_use_cases
        self._role_use_case = role_use_case
        self._audit_use_case = audit_use_case

    async def is_setup(self) -> bool:
        """Check if setup is performed.

        :return: bool (True if setup is performed, False otherwise)
        """
        query = select(
            exists(Directory).where(qa(Directory.parent_id).is_(None)),
        )
        retval = await self._session.scalars(query)
        return retval.one()

    async def create(self, dto: SetupDTO, data: list) -> None:
        async with self._session.begin_nested():
            try:
                await setup_enviroment(
                    self._session,
                    dn=dto.domain,
                    data=data,
                    password_validator=self._password_validator,
                )
                await self._session.flush()
                errors = await (
                    self
                    ._password_use_cases
                    .check_default_policy_password_violations(
                        password=dto.password,
                    )
                )  # fmt: skip
                if errors:
                    raise ForbiddenError(errors)

                await self._password_use_cases.create_policy()
                await self._role_use_case.create_domain_admins_role()
                await self._role_use_case.create_read_only_role()
                await self._audit_use_case.create_policies()
                await self._session.commit()
            except IntegrityError:
                await self._session.rollback()
                raise AlreadyConfiguredError(
                    "Setup already performed (locked)",
                )
