"""DHCP Manager Repository.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import CatalogueSetting

from .enums import DHCPManagerState

DHCP_MANAGER_STATE_NAME = "DHCPManagerState"


class DHCPManagerRepository:
    """Repository for managing DHCP configurations."""

    _session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the repository with a database session."""
        self._session = session

    async def get_state(self) -> DHCPManagerState | None:
        """Get the current state of the DHCP manager."""
        state = await self._session.scalar(
            select(CatalogueSetting)
            .filter(CatalogueSetting.name == DHCP_MANAGER_STATE_NAME),
        )  # fmt: skip
        return DHCPManagerState(state.value) if state else None

    async def change_state(self, state: DHCPManagerState) -> None:
        """Set the current state of the DHCP manager."""
        await self._session.execute(
            update(CatalogueSetting)
            .values({"value": state})
            .where(CatalogueSetting.name == DHCP_MANAGER_STATE_NAME),
        )

        await self._session.flush()

    async def ensure_state(self) -> DHCPManagerState:
        """Ensure the DHCP manager state."""
        current_state = await self.get_state()

        if current_state is None:
            self._session.add(
                CatalogueSetting(
                    name=DHCP_MANAGER_STATE_NAME,
                    value=DHCPManagerState.NOT_CONFIGURED,
                ),
            )

        await self._session.flush()

        return current_state or DHCPManagerState.NOT_CONFIGURED
