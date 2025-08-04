"""Utils for DHCP server API.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import CatalogueSetting

from .base import DHCP_MANAGER_STATE_NAME, DHCPManagerState


async def get_dhcp_state(
    session: AsyncSession,
) -> "DHCPManagerState":
    """Get or create DHCP manager state."""
    state = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == DHCP_MANAGER_STATE_NAME),
    )  # fmt: skip

    if state is None:
        session.add(
            CatalogueSetting(
                name=DHCP_MANAGER_STATE_NAME,
                value=DHCPManagerState.NOT_CONFIGURED,
            ),
        )
        await session.commit()
        return DHCPManagerState.NOT_CONFIGURED

    return DHCPManagerState(state.value)
