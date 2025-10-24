"""Password Policy DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Sequence, cast as tcast

from adaptix import P
from adaptix.conversion import get_converter, link_function
from sqlalchemy import (
    Integer,
    String,
    cast,
    delete,
    exists,
    func,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from abstract_dao import AbstractDAO
from entities import Attribute, Group, PasswordPolicy, User
from ldap_protocol.policies.password.exceptions import (
    PasswordPolicyAlreadyExistsError,
    PasswordPolicyBaseDnNotFoundError,
    PasswordPolicyCantChangeDefaultDomainError,
    PasswordPolicyCantDeleteError,
    PasswordPolicyDirIsNotUserError,
    PasswordPolicyNotFoundError,
    PasswordPolicyUpdatePrioritiesError,
)
from ldap_protocol.user_account_control import (
    UserAccountControlFlag as UacFlag,
    get_check_uac,
)
from ldap_protocol.utils.helpers import ft_now
from ldap_protocol.utils.queries import (
    get_base_directories,
    get_filter_from_path,
    get_groups,
)
from repo.pg.tables import queryable_attr as qa

from .dataclasses import (
    DefaultDomainPasswordPolicyPreset as DefaultDomainP,
    PasswordPolicyDTO,
    TurnoffPasswordPolicyPreset as TurnoffP,
    _PriorityT,
)


def _make_group_paths(password_policy: PasswordPolicy) -> list[str]:
    """Create a list of group paths from Password Policy."""
    return [group.directory.path_dn for group in password_policy.groups]


_convert_model_to_dto = get_converter(
    PasswordPolicy,
    PasswordPolicyDTO[int, int],
    recipe=[
        link_function(
            _make_group_paths,
            P[PasswordPolicyDTO[int, int]].group_paths,
        ),
    ],
)


class PasswordPolicyDAO(AbstractDAO[PasswordPolicyDTO, int]):
    """Password Policy DAO."""

    _session: AsyncSession

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        """Initialize Password Policy DAO with a database session."""
        self._session = session

    async def _get_total_count(self) -> int:
        """Count all Password Policies."""
        count = await self._session.scalar(
            select(func.count(qa(PasswordPolicy.id))),
        )
        return count or 0

    async def _get_all_raw(self) -> Sequence[PasswordPolicy]:
        """Get all raw (models) Password Policy."""
        policies = await self._session.scalars(
            select(PasswordPolicy)
            .options(
                selectinload(qa(PasswordPolicy.groups))
                .joinedload(qa(Group.directory)),
            )
            .order_by(qa(PasswordPolicy.priority)),
        )  # fmt: skip
        return policies.all()

    async def _get_raw(self, id_: int) -> PasswordPolicy | None:
        """Get one raw (model) Password Policy by ID."""
        policy = await self._session.scalar(
            select(PasswordPolicy)
            .options(
                selectinload(qa(PasswordPolicy.groups))
                .joinedload(qa(Group.directory)),
            )
            .filter_by(id=id_),
        )  # fmt: skip

        return policy

    async def _get_raw_by_name(self, name: str) -> PasswordPolicy | None:
        """Get one raw (model) Password Policy by name."""
        policy = await self._session.scalar(
            select(PasswordPolicy)
            .options(
                selectinload(qa(PasswordPolicy.groups))
                .joinedload(qa(Group.directory)),
            )
            .filter_by(name=name),
        )  # fmt: skip

        return policy

    async def _get_raw_domain_password_policy(self) -> PasswordPolicy | None:
        return await self._get_raw_by_name(DefaultDomainP.name)

    async def _build_default_domain_password_policy_dto(
        self,
    ) -> PasswordPolicyDTO[None, None]:
        """Build domain Password Policy."""
        base_dn_list = await get_base_directories(self._session)
        if not base_dn_list:
            raise PasswordPolicyBaseDnNotFoundError(
                "No base DN found in the LDAP directory.",
            )

        group_paths = [base_dn_list[0].path_dn]
        return PasswordPolicyDTO[None, None](
            priority=None,
            name=DefaultDomainP.name,
            group_paths=group_paths,
            password_history_length=DefaultDomainP.password_history_length,
            maximum_password_age_days=DefaultDomainP.maximum_password_age_days,
            minimum_password_age_days=DefaultDomainP.minimum_password_age_days,
            minimum_password_length=DefaultDomainP.minimum_password_length,
            password_must_meet_complexity_requirements=DefaultDomainP.password_must_meet_complexity_requirements,
        )

    async def _is_policy_already_exist(self, name: str) -> bool:
        _is_exists = await self._session.scalar(
            select(
                exists(PasswordPolicy)
                .where(qa(PasswordPolicy.name) == name),
            ),
        )  # fmt: skip
        return bool(_is_exists)

    async def get_domain_password_policy(self) -> PasswordPolicyDTO[int, int]:
        return await self.get_by_name(DefaultDomainP.name)

    async def get_all(self) -> list[PasswordPolicyDTO[int, int]]:
        """Get all Password Policies."""
        policies = await self._get_all_raw()
        return list(map(_convert_model_to_dto, policies))

    async def get_by_name(self, name: str) -> PasswordPolicyDTO[int, int]:
        """Get password policy by name."""
        policy = await self._get_raw_by_name(name)
        if not policy:
            raise PasswordPolicyNotFoundError("Password Policy not found.")
        return _convert_model_to_dto(policy)

    async def get(self, id_: int) -> PasswordPolicyDTO[int, int]:
        """Get one Password Policy."""
        policy = await self._get_raw(id_)
        if not policy:
            raise PasswordPolicyNotFoundError("Password Policy not found.")
        return _convert_model_to_dto(policy)

    async def get_password_policy_by_userdir_path_dn(
        self,
        path_dn: str,
    ) -> PasswordPolicyDTO[int, int]:
        """Get one Password Policy for one Directory by its path."""
        user = await self._session.scalar(
            select(User)
            .join(qa(User.directory))
            .where(get_filter_from_path(path_dn)),
        )  # fmt: skip

        if not user:
            raise PasswordPolicyDirIsNotUserError("Directory is not a User.")

        return await self.get_password_policy_for_user(user)

    async def create(self, dto: PasswordPolicyDTO[None, _PriorityT]) -> None:
        """Create one Password Policy."""
        if await self._is_policy_already_exist(dto.name):
            raise PasswordPolicyAlreadyExistsError(
                "Password Policy already exists",
            )

        priority = dto.priority or await self._get_total_count()
        if priority == 0:
            priority = 1

        domain_pwd_policy = await self._get_raw_domain_password_policy()
        if domain_pwd_policy and domain_pwd_policy.priority < priority:
            raise PasswordPolicyCantChangeDefaultDomainError(
                "Domain Password Policy must have the lowest priority.",
            )

        await self._session.execute(
            update(PasswordPolicy)
            .values(priority=PasswordPolicy.priority + 1)
            .where(priority <= qa(PasswordPolicy.priority)),
        )  # fmt: skip

        groups = await get_groups(dto.group_paths, self._session)
        password_policy = PasswordPolicy(
            priority=priority,
            name=dto.name,
            groups=groups,
            password_history_length=dto.password_history_length,
            maximum_password_age_days=dto.maximum_password_age_days,
            minimum_password_age_days=dto.minimum_password_age_days,
            minimum_password_length=dto.minimum_password_length,
            password_must_meet_complexity_requirements=dto.password_must_meet_complexity_requirements,
        )
        self._session.add(password_policy)
        await self._session.flush()

    async def create_default_domain_policy(self) -> None:
        """Create default domain Password Policy with default configuration."""
        if await self._is_policy_already_exist(DefaultDomainP.name):
            return

        dto = await self._build_default_domain_password_policy_dto()
        await self.create(dto)
        await self._session.flush()

    async def update(
        self,
        id_: int,
        dto: PasswordPolicyDTO[int, _PriorityT],
    ) -> None:
        """Update one Password Policy."""
        policy = await self._get_raw(id_)
        if not policy:
            raise PasswordPolicyNotFoundError("Password Policy not found.")

        if policy.name == DefaultDomainP.name and dto.name != policy.name:
            raise PasswordPolicyCantChangeDefaultDomainError(
                "Cannot change the name of the default domain Password Policy.",  # noqa: E501
            )

        domain_password_policy = await self.get_domain_password_policy()
        priority = dto.priority or await self._get_total_count()
        if domain_password_policy.priority < priority:
            raise PasswordPolicyCantChangeDefaultDomainError(
                "Domain Password Policy must have the lowest priority.",
            )

        if priority != policy.priority:
            policy.priority = priority
            await self._session.execute(
                update(PasswordPolicy)
                .values(priority=PasswordPolicy.priority + 1)
                .where(priority <= qa(PasswordPolicy.priority)),
            )  # fmt: skip

        policy.name = dto.name
        policy.groups = await get_groups(dto.group_paths, self._session)
        policy.password_history_length = dto.password_history_length
        policy.maximum_password_age_days = dto.maximum_password_age_days
        policy.minimum_password_age_days = dto.minimum_password_age_days
        policy.minimum_password_length = dto.minimum_password_length
        policy.password_must_meet_complexity_requirements = (
            dto.password_must_meet_complexity_requirements
        )

        await self._session.flush()

    async def delete(self, id_: int) -> None:
        """Delete one Password Policy."""
        total_count = await self._get_total_count()
        if total_count == 0:
            raise PasswordPolicyNotFoundError("Password Policies not found.")
        elif total_count == 1:
            raise PasswordPolicyCantDeleteError(
                "Cannot delete the last Password Policy.",
            )

        policy = await self.get(id_)
        if policy.name == DefaultDomainP.name:
            raise PasswordPolicyCantDeleteError(
                "Cannot delete the domain Password Policy.",
            )

        await self._session.execute(delete(PasswordPolicy).filter_by(id=id_))
        await self._session.flush()

        await self._session.execute(
            update(PasswordPolicy)
            .values(priority=PasswordPolicy.priority - 1)
            .where(policy.priority < qa(PasswordPolicy.priority)),
        )  # fmt: skip

        await self._session.flush()

    async def reset_domain_policy_to_default_config(self) -> None:
        """Reset domain Password Policy to default configuration using DefaultDomainPasswordPolicyPreset."""  # noqa: E501
        domain_policy = await self._get_raw_domain_password_policy()
        if not domain_policy:
            raise PasswordPolicyNotFoundError(
                "Domain Password Policy not found.",
            )

        dto = await self._build_default_domain_password_policy_dto()

        domain_policy.name = dto.name
        domain_policy.priority = await self._get_total_count()
        domain_policy.groups = await get_groups(dto.group_paths, self._session)
        domain_policy.password_history_length = dto.password_history_length
        domain_policy.maximum_password_age_days = dto.maximum_password_age_days
        domain_policy.minimum_password_age_days = dto.minimum_password_age_days
        domain_policy.minimum_password_length = dto.minimum_password_length
        domain_policy.password_must_meet_complexity_requirements = (
            dto.password_must_meet_complexity_requirements
        )

        await self._session.flush()

    async def update_priorities(self, new_priorities: dict[int, int]) -> None:
        """Update priority of all Password Policies."""
        if len(set(new_priorities.values())) != len(new_priorities.values()):
            raise PasswordPolicyUpdatePrioritiesError(
                "Priorities contain duplicates.",
            )

        total_count = await self._get_total_count()
        if len(new_priorities) != total_count:
            raise PasswordPolicyUpdatePrioritiesError(
                "Not all priorities set.",
            )

        domain_policy = await self.get_domain_password_policy()
        if new_priorities.get(domain_policy.id) != total_count:
            raise PasswordPolicyCantChangeDefaultDomainError(
                "Domain Password Policy must have the lowest priority.",
            )

        # NOTE: temporary negate priorities to avoid unique constraint conflicts  # noqa: E501
        await self._session.execute(
            update(PasswordPolicy)
            .values(priority=-PasswordPolicy.priority),
        )  # fmt: skip
        await self._session.flush()

        for policy in await self._get_all_raw():
            policy.priority = new_priorities.get(policy.id, policy.priority)
        await self._session.flush()

    async def turnoff(self, id_: int) -> None:
        """Turn off one Password Policy using TurnoffPasswordPolicyPreset."""
        policy = await self._get_raw(id_)
        if not policy:
            raise PasswordPolicyNotFoundError("Password Policy not found.")

        policy.password_history_length = TurnoffP.password_history_length
        policy.maximum_password_age_days = TurnoffP.maximum_password_age_days
        policy.minimum_password_age_days = TurnoffP.minimum_password_age_days
        policy.minimum_password_length = TurnoffP.minimum_password_length
        policy.password_must_meet_complexity_requirements = TurnoffP.password_must_meet_complexity_requirements  # noqa: E501  # fmt: skip

        await self._session.flush()

    async def get_password_policy_for_user(
        self,
        user: User,
    ) -> PasswordPolicyDTO[int, int]:
        """Get one Password Policy for one User.

        The password policy is calculated only for the "User" entity
        based on its [the user's] groups with the lowest priority value.

        If no policy is assigned, the DefaultDomainPasswordPolicy is applied.
        For all other entities (not "User"), the DefaultDomainPasswordPolicy is applied.
        """  # noqa: E501
        policy = await self._session.scalar(
            select(PasswordPolicy)
            .join(qa(PasswordPolicy.groups))
            .join(qa(Group.users))
            .options(
                selectinload(qa(PasswordPolicy.groups)).joinedload(
                    qa(Group.directory),
                ),
            )
            .where(qa(Group.users).contains(user))
            .order_by(qa(PasswordPolicy.priority).asc())
            .limit(1),
        )
        dto = _convert_model_to_dto(policy) if policy else None

        if not dto:
            dto = await self.get_domain_password_policy()

        return dto

    async def get_or_create_pwd_last_set(
        self,
        directory_id: int,
    ) -> str | None:
        """Get or create password last set attribute."""
        plset_attribute = await self._session.scalar(
            select(Attribute)
            .filter_by(directory_id=directory_id, name="pwdLastSet"),
        )  # fmt: skip

        if not plset_attribute:
            plset_attribute = Attribute(
                directory_id=directory_id,
                name="pwdLastSet",
                value=ft_now(),
            )

            self._session.add(plset_attribute)

        return plset_attribute.value

    async def post_save_password_actions(self, user: User) -> None:
        """Post save actions for password update."""
        await self._session.execute(  # update bind reject attribute
            update(Attribute)
            .values({"value": ft_now()})
            .filter_by(directory_id=user.directory_id, name="pwdLastSet"),
        )

        new_value = cast(
            cast(Attribute.value, Integer).op("&")(~UacFlag.PASSWORD_EXPIRED),
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

        user.password_history.append(tcast("str", user.password))
        await self._session.flush()

    async def is_password_change_restricted(
        self,
        user_directory_id: int,
    ) -> bool:
        """Check if user is restricted from changing password via UAC flag.

        :param int user_directory_id: user's directory ID
        :return bool: True if user is restricted, False otherwise
        """
        check_uac = await get_check_uac(self._session, user_directory_id)
        return check_uac(UacFlag.PASSWD_CANT_CHANGE)
