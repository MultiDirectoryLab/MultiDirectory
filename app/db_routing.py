"""Engine registry and routing session.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Any, Sequence

from sqlalchemy import Delete, Insert, Update, exc as sa_exc
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.orm import Session


class EngineRegistry:
    _master_engine: AsyncEngine
    _replica_engine: AsyncEngine | None

    def __init__(
        self,
        master_engine: AsyncEngine,
        replica_engine: AsyncEngine | None,
    ) -> None:
        self._master_engine = master_engine
        self._replica_engine = replica_engine

    def get_master_engine(self) -> AsyncEngine:
        return self._master_engine

    def get_replica_engine(self) -> AsyncEngine:
        if self._replica_engine is None:
            raise RuntimeError("Replica engine is not configured")
        return self._replica_engine

    def get_sync_master_engine(self) -> Engine:
        return self._master_engine.sync_engine

    def get_sync_replica_engine(self) -> Engine:
        if self._replica_engine is None:
            raise RuntimeError("Replica engine is not configured")
        return self._replica_engine.sync_engine


class RoutingSession(Session):
    _force_master: bool = False

    @property
    def engine_registry(self) -> EngineRegistry:
        return self.info["engine_registry"]

    def set_force_master(self, value: bool) -> None:
        self._force_master = value

    def get_bind(self, mapper=None, clause=None) -> Engine:  # type: ignore  # noqa: ARG002
        if isinstance(clause, Update | Insert | Delete):
            return self.engine_registry.get_sync_master_engine()

        if self._force_master or self._flushing:
            return self.engine_registry.get_sync_master_engine()
        else:
            return self.engine_registry.get_sync_replica_engine()

    def flush(self, objects: Sequence[Any] | None = None) -> None:
        if self._flushing:
            raise sa_exc.InvalidRequestError("Session is already flushing")

        if self._is_clean():
            return
        try:
            self._flushing = True
            self._flush(objects)
        finally:
            self._flushing = False
            self._force_master = True
