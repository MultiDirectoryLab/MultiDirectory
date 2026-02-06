"""Check Master Use Case.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Protocol

from abstract_service import AbstractService


class MasterGatewayProtocol(Protocol):
    """Master DB Gateway Protocol."""

    async def check_master(self) -> bool: ...


class MasterCheckUseCase(AbstractService):
    """Check Master Use Case."""

    _master_gateway: MasterGatewayProtocol

    def __init__(self, master_gateway: MasterGatewayProtocol) -> None:
        self._master_gateway = master_gateway

    async def check_master(self) -> bool:
        return await self._master_gateway.check_master()
