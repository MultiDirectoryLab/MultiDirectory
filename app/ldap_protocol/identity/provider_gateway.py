"""Gateway for accessing identity data from the database.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from entities import Group, Role, User
from enums import AuthorizationRules
from repo.pg.tables import queryable_attr as qa


class IdentityProviderGateway:
    """Gateway for loading Identity data from the database."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize gateway.

        Args:
            session: Async SQLAlchemy session used to query user entities.

        """
        self.session = session

    async def get_user(self, user_id: int) -> User | None:
        """Return user entity with related aggregates eagerly loaded.

        Args:
            user_id: Identifier of the user to fetch.

        Returns:
            User | None: Fully populated user entity or ``None`` if missing.

        """
        return await self.session.scalar(
            select(User)
            .filter_by(id=user_id)
            .options(joinedload(qa(User.directory)))
            .options(
                selectinload(qa(User.groups)).selectinload(qa(Group.roles)),
            ),
        )

    async def get_user_permissions(
        self,
        role_ids: list[int],
    ) -> AuthorizationRules:
        permissions = await self.session.scalars(
            select(qa(Role.permissions))
            .where(qa(Role.id).in_(role_ids)),
        )  # fmt: skip

        return AuthorizationRules(sum(permissions))
