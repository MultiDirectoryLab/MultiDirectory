"""NetworkPolicyService: Class for encapsulating network policy business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Network

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


class NetworkPolicyService:
    """Service for network policy business logic."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the service with a database session.

        :param session: SQLAlchemy AsyncSession
        """
        self.session = session

    async def add_policy(self, policy: Policy) -> PolicyResponse:
        """Add a new network policy.

        :param policy: Policy (pydantic schema)
        :raises PolicyError: if an error occurs
        :return: PolicyResponse
        """
        new_policy = self._build_network_policy_from_schema(policy)
        group_dns = await self._set_policy_groups(
            new_policy, policy.groups, "groups"
        )
        mfa_group_dns = await self._set_policy_groups(
            new_policy, policy.mfa_groups, "mfa_groups"
        )
        try:
            self.session.add(new_policy)
            await self.session.commit()
        except IntegrityError:
            raise PolicyError("Entry already exists")
        await self.session.refresh(new_policy)
        return self._build_policy_response(
            new_policy, group_dns, mfa_group_dns
        )

    async def get_policies(self) -> list[PolicyResponse]:
        """Get a list of all network policies.

        :return: list of PolicyResponse
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
            self._build_policy_response_from_model(policy)
            for policy in policies
        ]

    async def delete_policy(self, policy_id: int) -> None:
        """Delete a network policy by its ID.

        :param policy_id: int
        :raises NotFoundError: if the policy is not found
        :raises
            PolicyError: if only one active policy remains
        :return: None
        """
        policy = await self.session.get(
            NetworkPolicy, policy_id, with_for_update=True
        )
        if not policy:
            raise NotFoundError("Policy not found")
        await self.check_policy_count()
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

    async def switch_policy(self, policy_id: int) -> bool:
        """Toggle the enabled state of a network policy.

        :param policy_id: int
        :raises NotFoundError: if the policy is not found
        :raises PolicyError: if only one active policy remains
        :return: bool
        """
        policy = await self.session.get(
            NetworkPolicy, policy_id, with_for_update=True
        )
        if not policy:
            raise NotFoundError("Policy not found")
        if policy.enabled:
            await self.check_policy_count()
        policy.enabled = not policy.enabled
        await self.session.commit()
        return True

    async def update_policy(self, request: PolicyUpdate) -> PolicyResponse:
        """Update an existing network policy.

        :param request: PolicyUpdate (pydantic schema)
        :raises NotFoundError: if the policy is not found
        :raises PolicyError: if an error occurs
        :return: PolicyResponse
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
        self._update_policy_fields(selected_policy, request)
        groups_path_dn = await self._set_policy_groups(
            selected_policy, request.groups, "groups"
        )
        mfa_groups_path_dn = await self._set_policy_groups(
            selected_policy, request.mfa_groups, "mfa_groups"
        )
        try:
            await self.session.commit()
        except IntegrityError:
            raise PolicyError("Entry already exists")
        return self._build_policy_response(
            selected_policy, groups_path_dn, mfa_groups_path_dn
        )

    async def swap_policy(self, swap: SwapRequest) -> SwapResponse:
        """Swap the priorities of two network policies.

        :param swap: SwapRequest (pydantic schema)
        :raises NotFoundError: if either policy is not found
        :return: SwapResponse
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
        return self._build_swap_response(policy1, policy2)

    async def check_policy_count(self) -> None:
        """Check that there is more than one active policy.

        :raises PolicyError: if only one active policy remains
        :return: None
        """
        count = await self.session.scalars(
            (
                select(func.count())
                .select_from(NetworkPolicy)
                .filter_by(enabled=True)
            ),
        )
        if count.one() == 1:
            raise PolicyError("At least one policy should be active")

    def _build_network_policy_from_schema(
        self,
        policy: Policy,
    ) -> NetworkPolicy:
        """Create a NetworkPolicy ORM object from a Policy schema."""
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

    async def _set_policy_groups(
        self,
        policy_obj: NetworkPolicy,
        group_dns: list[str] | None,
        attr_name: str,
    ) -> list[str]:
        """Set groups or mfa_groups for a policy object and return their DNs.

        :param policy_obj: NetworkPolicy ORM object
        :param group_dns: list of group DNs or None
        :param attr_name: 'groups' or 'mfa_groups'
        :return: list of group DNs
        """
        if group_dns is not None:
            if len(group_dns) > 0:
                groups = await get_groups(group_dns, self.session)
                setattr(policy_obj, attr_name, groups)
                return [group.directory.path_dn for group in groups]
            else:
                getattr(policy_obj, attr_name).clear()
        return []

    def _update_policy_fields(
        self,
        policy: NetworkPolicy,
        request: PolicyUpdate,
    ) -> None:
        """Update fields of a NetworkPolicy from a PolicyUpdate schema."""
        for field in PolicyUpdate.fields_map:
            value = getattr(request, field)
            if value is not None:
                setattr(policy, field, value)
        if request.netmasks:
            policy.netmasks = request.complete_netmasks
            policy.raw = request.model_dump(mode="json")["netmasks"]

    def _build_policy_response(
        self,
        policy: NetworkPolicy,
        group_dns: list[str],
        mfa_group_dns: list[str],
    ) -> PolicyResponse:
        """Build a PolicyResponse from a NetworkPolicy and group DNs."""
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
            groups=group_dns,
            mfa_status=policy.mfa_status,
            mfa_groups=mfa_group_dns,
            is_http=policy.is_http,
            is_ldap=policy.is_ldap,
            is_kerberos=policy.is_kerberos,
            bypass_no_connection=policy.bypass_no_connection,
            bypass_service_failure=policy.bypass_service_failure,
        )

    def _build_policy_response_from_model(
        self,
        policy: NetworkPolicy,
    ) -> PolicyResponse:
        """Build a PolicyResponse from a NetworkPolicy ORM object."""
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

    def _build_swap_response(
        self,
        policy1: NetworkPolicy,
        policy2: NetworkPolicy,
    ) -> SwapResponse:
        """Build a SwapResponse from two NetworkPolicy ORM objects."""
        return SwapResponse(
            first_policy_id=policy1.id,
            first_policy_priority=policy1.priority,
            second_policy_id=policy2.id,
            second_policy_priority=policy2.priority,
        )
