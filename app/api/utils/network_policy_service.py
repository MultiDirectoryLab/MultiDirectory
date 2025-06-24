"""NetworkPolicyService: Class for encapsulating network policy business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Network

from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse
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
    :raises HTTPException: 422 если активна только одна политика.
    """
    count = await session.scalars(
        (
            select(func.count())
            .select_from(NetworkPolicy)
            .filter_by(enabled=True)
        ),
    )

    if count.one() == 1:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "At least one policy should be active",
        )


class NetworkPolicyService:
    """Сервис сетевых политик."""

    def __init__(self, session: AsyncSession) -> None:
        """Инициализация зависимостей сервиса (через DI).

        :param session: SQLAlchemy AsyncSession
        """
        self.session = session

    async def add_policy(self, policy: Policy) -> PolicyResponse:
        """Добавить новую сетевую политику.

        :param policy: Policy (pydantic schema)
        :raises PolicyError: при ошибке
        :return: PolicyResponse.
        """
        new_policy = NetworkPolicy(
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
        group_dns = []
        mfa_group_dns = []
        if policy.groups:
            groups = await get_groups(policy.groups, self.session)
            new_policy.groups = groups
            group_dns = [group.directory.path_dn for group in groups]
        if policy.mfa_groups:
            mfa_groups = await get_groups(policy.mfa_groups, self.session)
            new_policy.mfa_groups = mfa_groups
            mfa_group_dns = [group.directory.path_dn for group in mfa_groups]
        try:
            self.session.add(new_policy)
            await self.session.commit()
        except IntegrityError:
            raise PolicyError("Entry already exists")
        await self.session.refresh(new_policy)
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
        """Получить список всех политик.

        :return: list[PolicyResponse].
        """
        groups = selectinload(NetworkPolicy.groups).selectinload(
            Group.directory
        )
        mfa_groups = selectinload(NetworkPolicy.mfa_groups).selectinload(
            Group.directory
        )
        policies = await self.session.scalars(
            select(NetworkPolicy)
            .options(groups, mfa_groups)
            .order_by(NetworkPolicy.priority.asc()),
        )
        return [
            PolicyResponse(
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
            for policy in policies
        ]

    async def delete_policy(
        self, policy_id: int, request: Request
    ) -> RedirectResponse:
        """Удалить политику по id.

        :param policy_id: int
        :param request: Request
        :raises NotFoundError: если политика не найдена
        :raises PolicyError:
            если активна только одна политика или на ошибка базы данных
        :return: RedirectResponse.
        """
        policy = await self.session.get(
            NetworkPolicy, policy_id, with_for_update=True
        )
        if not policy:
            raise NotFoundError("Policy not found")
        await check_policy_count(self.session)
        async with self.session.begin_nested():
            await self.session.delete(policy)
            await self.session.flush()
            await self.session.execute(
                (
                    update(NetworkPolicy)
                    .values({"priority": NetworkPolicy.priority - 1})
                    .filter(NetworkPolicy.priority > policy.priority)
                ),
            )
            await self.session.commit()
        return RedirectResponse(
            request.url_for("policy"),
            status_code=status.HTTP_303_SEE_OTHER,
            headers=request.headers,
        )

    async def switch_policy(self, policy_id: int) -> bool:
        """Переключить состояние политики (enable/disable).

        :param policy_id: int
        :raises NotFoundError: если политика не найдена
        :raises PolicyError: если активна только одна политика
        :return: bool.
        """
        policy = await self.session.get(
            NetworkPolicy, policy_id, with_for_update=True
        )
        if not policy:
            raise NotFoundError("Policy not found")
        if policy.enabled:
            await check_policy_count(self.session)
        policy.enabled = not policy.enabled
        await self.session.commit()
        return True

    async def update_policy(self, request: PolicyUpdate) -> PolicyResponse:
        """Обновить политику.

        :param request: PolicyUpdate (pydantic schema)
        :raises NotFoundError: если политика не найдена
        :raises PolicyError: при ошибке
        :return: PolicyResponse.
        """
        selected_policy = await self.session.get(
            NetworkPolicy,
            request.id,
            with_for_update=True,
            options=[
                selectinload(NetworkPolicy.groups),
                selectinload(NetworkPolicy.mfa_groups),
            ],
        )
        if not selected_policy:
            raise NotFoundError("Policy not found")
        for field in PolicyUpdate.fields_map:
            value = getattr(request, field)
            if value is not None:
                setattr(selected_policy, field, value)
        if request.netmasks:
            selected_policy.netmasks = request.complete_netmasks
            selected_policy.raw = request.model_dump(mode="json")["netmasks"]
        groups_path_dn = []
        if request.groups is not None and len(request.groups) > 0:
            groups = await get_groups(request.groups, self.session)
            selected_policy.groups = groups
            groups_path_dn = [group.directory.path_dn for group in groups]
        elif request.groups is not None and len(request.groups) == 0:
            selected_policy.groups.clear()
        mfa_groups_path_dn = []
        if request.mfa_groups is not None and len(request.mfa_groups) > 0:
            mfa_groups = await get_groups(request.mfa_groups, self.session)
            selected_policy.mfa_groups = mfa_groups
            mfa_groups_path_dn = [
                group.directory.path_dn for group in mfa_groups
            ]
        elif request.mfa_groups is not None and len(request.mfa_groups) == 0:
            selected_policy.mfa_groups.clear()
        try:
            await self.session.commit()
        except IntegrityError:
            raise PolicyError("Entry already exists")
        return PolicyResponse(
            id=selected_policy.id,
            name=selected_policy.name,
            netmasks=[
                n
                for n in selected_policy.netmasks
                if isinstance(n, IPv4Network)
            ],
            raw=list(selected_policy.raw)
            if isinstance(selected_policy.raw, list | tuple)
            else [str(selected_policy.raw)],
            enabled=selected_policy.enabled,
            priority=selected_policy.priority,
            groups=groups_path_dn,
            mfa_status=selected_policy.mfa_status,
            mfa_groups=mfa_groups_path_dn,
            is_http=selected_policy.is_http,
            is_ldap=selected_policy.is_ldap,
            is_kerberos=selected_policy.is_kerberos,
            bypass_no_connection=selected_policy.bypass_no_connection,
            bypass_service_failure=selected_policy.bypass_service_failure,
        )

    async def swap_policy(self, swap: SwapRequest) -> SwapResponse:
        """Поменять приоритеты двух политик.

        :param swap: SwapRequest (pydantic schema)
        :raises NotFoundError: если какая-то политика не найдена
        :return: SwapResponse.
        """
        policy1 = await self.session.get(
            NetworkPolicy,
            swap.first_policy_id,
            with_for_update=True,
        )
        policy2 = await self.session.get(
            NetworkPolicy,
            swap.second_policy_id,
            with_for_update=True,
        )
        if not policy1 or not policy2:
            raise NotFoundError("Policy not found")
        policy1.priority, policy2.priority = policy2.priority, policy1.priority
        await self.session.commit()
        return SwapResponse(
            first_policy_id=policy1.id,
            first_policy_priority=policy1.priority,
            second_policy_id=policy2.id,
            second_policy_priority=policy2.priority,
        )
