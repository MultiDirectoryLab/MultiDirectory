"""Tests for RID Manager."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from enums import SidPrefix
from ldap_protocol.rid_manager import RIDManagerUseCase
from ldap_protocol.rid_manager.object_sid_gateway import ObjectSIDGateway
from ldap_protocol.rid_manager.object_sid_use_case import ObjectSIDUseCase
from ldap_protocol.rid_manager.rid_manager_gateway import RIDManagerGateway
from ldap_protocol.rid_manager.rid_set_gateway import RIDSetGateway
from ldap_protocol.rid_manager.rid_set_use_case import RIDSetUseCase
from ldap_protocol.rid_manager.utils import from_qword, to_qword


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_rid_manager_allocate_pool(
    rid_manager_use_case: RIDManagerUseCase,
    rid_manager_gateway: RIDManagerGateway,
) -> None:
    """Test RID Manager get domain controller."""
    available_pool = await rid_manager_gateway.get_rid_available_pool()

    await rid_manager_use_case.allocate_pool()
    new_available_pool = await rid_manager_gateway.get_rid_available_pool()
    lower, _ = from_qword(available_pool)
    new_lower, _ = from_qword(new_available_pool)

    assert new_lower == lower + RIDManagerUseCase.RID_BLOCK_SIZE


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_next_rid(
    rid_set_use_case: RIDSetUseCase,
    rid_manager_use_case: RIDManagerUseCase,
) -> None:
    """Test RID Manager get domain controller."""
    dc = await rid_manager_use_case.get_domain_controller()
    rid_set = await rid_set_use_case.get(dc)
    rid_set_id = rid_set.id
    next_rid = await rid_set_use_case.allocate_next_rid(rid_set_id)
    new_next_rid = await rid_set_use_case.allocate_next_rid(rid_set_id)
    assert new_next_rid == next_rid + 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_rid_set_reset_pool(
    rid_set_use_case: RIDSetUseCase,
    rid_manager_use_case: RIDManagerUseCase,
    rid_manager_gateway: RIDManagerGateway,
    rid_set_gateway: RIDSetGateway,
) -> None:
    """Test RID Set pool reset."""
    dc = await rid_manager_use_case.get_domain_controller()
    rid_set = await rid_set_use_case.get(dc)
    rid_set_id = rid_set.id

    available_pool_before = await rid_manager_gateway.get_rid_available_pool()
    lower_before, _ = from_qword(available_pool_before)
    previous_pool_before = (
        await rid_set_gateway.get_rid_previous_allocation_pool(rid_set_id)
    )

    _, upper = from_qword(previous_pool_before)
    await rid_set_gateway.update_next_rid(rid_set_id, upper - 1)

    current_next_rid = await rid_set_gateway.get_rid_next_rid(rid_set_id)
    assert (
        rid_set_use_case.is_pool_exceeded(
            current_next_rid,
            previous_pool_before,
        )
        is True
    )

    next_rid = await rid_set_use_case.allocate_next_rid(rid_set_id)
    current_next_rid = await rid_set_gateway.get_rid_next_rid(rid_set_id)
    previous_pool_mid = await rid_set_gateway.get_rid_previous_allocation_pool(
        rid_set_id,
    )
    assert (
        rid_set_use_case.is_pool_exceeded(
            current_next_rid,
            previous_pool_mid,
        )
        is False
    )

    available_pool_after = await rid_manager_gateway.get_rid_available_pool()
    lower_after, _ = from_qword(available_pool_after)
    allocation_pool_after = await rid_set_gateway.get_rid_allocation_pool(
        rid_set_id,
    )
    previous_pool_after = (
        await rid_set_gateway.get_rid_previous_allocation_pool(
            rid_set_id,
        )
    )

    assert lower_after == lower_before + RIDManagerUseCase.RID_BLOCK_SIZE
    assert previous_pool_after == to_qword(
        next_rid,
        lower_before + RIDManagerUseCase.RID_BLOCK_SIZE,
    )
    assert allocation_pool_after == previous_pool_before


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_object_sid_add_updates_next_rid_and_prefix(
    session: AsyncSession,
    object_sid_use_case: ObjectSIDUseCase,
    object_sid_gateway: ObjectSIDGateway,
    rid_set_use_case: RIDSetUseCase,
    rid_set_gateway: RIDSetGateway,
    rid_manager_use_case: RIDManagerUseCase,
) -> None:
    dc = await rid_manager_use_case.get_domain_controller()
    rid_set = await rid_set_use_case.get(dc)
    rid_set_id = rid_set.id
    dc_id = dc.id

    next_before = await rid_set_gateway.get_rid_next_rid(rid_set_id)

    await object_sid_use_case.add(directory_id=dc_id)
    await session.flush()
    next_after = await rid_set_gateway.get_rid_next_rid(rid_set_id)
    assert next_after == next_before + 1

    sid_domain_attr = await object_sid_gateway.get(dc_id)
    assert sid_domain_attr.startswith("S-1-5-21-")

    await object_sid_use_case.add(
        directory_id=rid_set_id,
        rid=512,
        sid_prefix=SidPrefix.BUILT_IN_DOMAIN,
    )
    await session.flush()
    next_after_builtin = await rid_set_gateway.get_rid_next_rid(rid_set_id)
    assert next_after_builtin == next_after

    sid_builtin_attr = await object_sid_gateway.get(rid_set_id)
    assert sid_builtin_attr.startswith("S-1-5-32-")
    assert sid_builtin_attr != sid_domain_attr
