"""NetworkPolicyService: Class for encapsulating network policy business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Network
from typing import Literal

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.network.schema import (
    Policy,
    PolicyResponse,
    PolicyUpdate,
    SwapRequest,
    SwapResponse,
)
from api.utils.exceptions import NotFoundError, PolicyError
from ldap_protocol.utils.queries import get_groups
from models import Group, NetworkPolicy


async def check_policy_count(session: AsyncSession) -> None:
    """Проверить, что активна только одна политика.

    :param session: AsyncSession
    :raises PolicyError: если активна только одна политика.
    """
    count = await session.scalars(
        (
            select(func.count())
            .select_from(NetworkPolicy)
            .filter_by(enabled=True)
        ),
    )

    if count.one() == 1:
        raise PolicyError("At least one policy should be active")


class NetworkPolicyService:
    """Сервис сетевых политик."""

    def __init__(self, session: AsyncSession) -> None:
        """Инициализация зависимостей сервиса (через DI).

        :param session: SQLAlchemy AsyncSession
        """
        self._session = session

    async def add_policy(self, policy: Policy) -> PolicyResponse:
        """Добавить новую сетевую политику."""
        new_policy = self._build_network_policy(policy)
        group_dns = await self._attach_policy_groups(
            new_policy, policy.groups, "groups"
        )
        mfa_group_dns = await self._attach_policy_groups(
            new_policy, policy.mfa_groups, "mfa_groups"
        )
        try:
            self._session.add(new_policy)
            await self._session.commit()
        except IntegrityError:
            raise PolicyError("Entry already exists")
        await self._session.refresh(new_policy)
        return self._build_policy_response(
            new_policy, group_dns, mfa_group_dns
        )

    def _build_network_policy(self, policy: Policy) -> NetworkPolicy:
        return NetworkPolicy(
            name=policy.name,
            netmasks=policy.complete_netmasks,
            priority=policy.priority,
            raw=policy.model_dump(mode="json")["netmasks"],
            mfa_status=policy.mfa_status,
            is_http=policy.is_http,
            is_ldap=policy.is_ldap,
            is_kerberos=policy.is_kerberos,
            bypass_no_connection=policy.bypass_no_connection,
            bypass_service_failure=policy.bypass_service_failure,
        )

    async def _attach_policy_groups(
        self,
        policy_obj: NetworkPolicy,
        group_dns: list[str] | None,
        attr_name: Literal["mfa_groups", "groups"],
    ) -> list[str]:
        if not group_dns:
            return []
        group_objs = await get_groups(group_dns, self._session)
        setattr(policy_obj, attr_name, group_objs)
        return [group.directory.path_dn for group in group_objs]

    def _build_policy_response(
        self,
        new_policy: NetworkPolicy,
        group_dns: list[str],
        mfa_group_dns: list[str],
    ) -> PolicyResponse:
        return PolicyResponse(
            id=new_policy.id,
            name=new_policy.name,
            netmasks=[
                n for n in new_policy.netmasks if isinstance(n, IPv4Network)
            ],
            raw=list(new_policy.raw)
            if isinstance(new_policy.raw, list | tuple)
            else [str(new_policy.raw)],
            enabled=new_policy.enabled,
            priority=new_policy.priority,
            groups=group_dns,
            mfa_status=new_policy.mfa_status,
            mfa_groups=mfa_group_dns,
            is_http=new_policy.is_http,
            is_ldap=new_policy.is_ldap,
            is_kerberos=new_policy.is_kerberos,
            bypass_no_connection=new_policy.bypass_no_connection,
            bypass_service_failure=new_policy.bypass_service_failure,
        )

    async def get_policies(self) -> list[PolicyResponse]:
        """Получить список всех политик."""
        groups = selectinload(NetworkPolicy.groups).selectinload(
            Group.directory
        )
        mfa_groups = selectinload(NetworkPolicy.mfa_groups).selectinload(
            Group.directory
        )
        policies = await self._session.scalars(
            select(NetworkPolicy)
            .options(groups, mfa_groups)
            .order_by(NetworkPolicy.priority.asc()),
        )
        return [
            self._build_policy_response_from_model(policy)
            for policy in policies
        ]

    def _build_policy_response_from_model(
        self,
        policy: NetworkPolicy,
    ) -> PolicyResponse:
        return PolicyResponse(
            id=policy.id,
            name=policy.name,
            netmasks=[
                n for n in policy.netmasks if isinstance(n, IPv4Network)
            ],
            raw=list(policy.raw)
            if isinstance(policy.raw, list | tuple)
            else [str(policy.raw)],
            enabled=policy.enabled,
            priority=policy.priority,
            groups=[group.directory.path_dn for group in policy.groups],
            mfa_status=policy.mfa_status,
            mfa_groups=[
                group.directory.path_dn for group in policy.mfa_groups
            ],
            is_http=policy.is_http,
            is_ldap=policy.is_ldap,
            is_kerberos=policy.is_kerberos,
            bypass_no_connection=policy.bypass_no_connection,
            bypass_service_failure=policy.bypass_service_failure,
        )

    async def delete_policy(self, policy_id: int) -> bool:
        """Удалить политику по id."""
        policy = await self._get_policy_or_404(policy_id)
        await check_policy_count(self._session)
        await self._delete_and_reorder(policy)
        return True

    async def _get_policy_or_404(self, policy_id: int) -> NetworkPolicy:
        policy = await self._session.get(
            NetworkPolicy, policy_id, with_for_update=True
        )
        if not policy:
            raise NotFoundError("Policy not found")
        return policy

    async def _delete_and_reorder(self, policy: NetworkPolicy) -> None:
        async with self._session.begin_nested():
            await self._session.delete(policy)
            await self._session.flush()
            await self._reorder_priorities_after_delete(policy.priority)
            await self._session.commit()

    async def _reorder_priorities_after_delete(
        self,
        deleted_priority: int,
    ) -> None:
        await self._session.execute(
            (
                update(NetworkPolicy)
                .values({"priority": NetworkPolicy.priority - 1})
                .filter(NetworkPolicy.priority > deleted_priority)
            ),
        )

    async def switch_policy(self, policy_id: int) -> bool:
        """Переключить состояние политики (enable/disable).

        :param policy_id: int
        :raises NotFoundError: если политика не найдена
        :raises PolicyError: если активна только одна политика
        :return: bool.
        """
        policy = await self._session.get(
            NetworkPolicy, policy_id, with_for_update=True
        )
        if not policy:
            raise NotFoundError("Policy not found")
        if policy.enabled:
            await check_policy_count(self._session)
        policy.enabled = not policy.enabled
        await self._session.commit()
        return True

    async def update_policy(self, request: PolicyUpdate) -> PolicyResponse:
        """Обновить политику."""
        selected_policy = await self._get_policy_or_404(request.id)
        self._update_policy_fields(selected_policy, request)
        groups_path_dn = await self._attach_policy_groups(
            selected_policy, request.groups, "groups"
        )
        mfa_groups_path_dn = await self._attach_policy_groups(
            selected_policy, request.mfa_groups, "mfa_groups"
        )
        try:
            await self._session.commit()
        except IntegrityError:
            raise PolicyError("Entry already exists")
        return self._build_policy_response(
            selected_policy, groups_path_dn, mfa_groups_path_dn
        )

    def _update_policy_fields(
        self, policy: NetworkPolicy, request: PolicyUpdate
    ) -> None:
        for field in PolicyUpdate.fields_map:
            value = getattr(request, field)
            if value is not None:
                setattr(policy, field, value)
        if request.netmasks:
            policy.netmasks = request.complete_netmasks
            policy.raw = request.model_dump(mode="json")["netmasks"]

    async def swap_policy(self, swap: SwapRequest) -> SwapResponse:
        """Поменять приоритеты двух политик."""
        policy1 = await self._get_policy_or_404(swap.first_policy_id)
        policy2 = await self._get_policy_or_404(swap.second_policy_id)
        self._swap_priorities(policy1, policy2)
        await self._session.commit()
        return self._build_swap_response(policy1, policy2)

    def _swap_priorities(
        self, policy1: NetworkPolicy, policy2: NetworkPolicy
    ) -> None:
        policy1.priority, policy2.priority = policy2.priority, policy1.priority

    def _build_swap_response(
        self, policy1: NetworkPolicy, policy2: NetworkPolicy
    ) -> SwapResponse:
        return SwapResponse(
            first_policy_id=policy1.id,
            first_policy_priority=policy1.priority,
            second_policy_id=policy2.id,
            second_policy_priority=policy2.priority,
        )
