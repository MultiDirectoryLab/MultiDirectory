"""Gateway for accessing identity data from the database.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import Integer, String, cast, literal, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from entities import Attribute, Group, Role, User
from enums import AuthorizationRules
from ldap_protocol.utils.helpers import ft_now
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

        return AuthorizationRules.combine(permissions)

    async def update_bad_pwd_attrs(
        self,
        user: User,
        is_increase: bool,
    ) -> None:
        await self.__update_bad_pwd_count(user, is_increase)
        await self.__update_bad_pwd_time(user, is_increase)
        await self.session.commit()

    async def __update_bad_pwd_count(
        self,
        user: User,
        is_increase: bool,
    ) -> None:
        """Increment the bad password count for a user."""
        if is_increase:
            new_value = cast(qa(Attribute.value), Integer) + 1
        else:
            new_value = literal(0)

        q = (
            update(Attribute)
            .values(value=cast(new_value, String))
            .filter_by(
                directory_id=user.directory_id,
                name="badPwdCount",
            )
            .execution_options(synchronize_session=False)
        )
        await self.session.execute(q)

    async def __update_bad_pwd_time(
        self,
        user: User,
        is_increase: bool,
    ) -> None:
        if is_increase:
            await self.session.execute(  # update bad password time attribute
                update(Attribute)
                .values({"value": ft_now()})
                .filter_by(
                    directory_id=user.directory_id,
                    name="badPasswordTime",
                ),
            )
