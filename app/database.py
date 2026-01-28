"""Database configuration and routing session.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Any, Sequence

from loguru import logger
from sqlalchemy import Delete, Insert, Update, exc as sa_exc
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session

from config import Settings

settings = Settings.from_os()

engines = {
    "master": create_async_engine(
        str(settings.POSTGRES_URI),
        pool_size=settings.INSTANCE_DB_POOL_SIZE,
        max_overflow=settings.INSTANCE_DB_POOL_OVERFLOW,
        pool_timeout=settings.INSTANCE_DB_POOL_TIMEOUT,
        pool_recycle=settings.INSTANCE_DB_POOL_RECYCLE,
        pool_pre_ping=False,
        future=True,
        echo=False,
        logging_name="master",
        connect_args={"connect_timeout": settings.POSTGRES_CONNECT_TIMEOUT},
    ),
}
if settings.POSTGRES_RW_MODE == "replication":
    engines["replica"] = create_async_engine(
        str(settings.REPLICA_POSTGRES_URI),
        pool_size=settings.INSTANCE_DB_POOL_SIZE,
        max_overflow=settings.INSTANCE_DB_POOL_OVERFLOW,
        pool_timeout=settings.INSTANCE_DB_POOL_TIMEOUT,
        pool_recycle=settings.INSTANCE_DB_POOL_RECYCLE,
        pool_pre_ping=False,
        future=True,
        echo=False,
        logging_name="replica",
        connect_args={
            "connect_timeout": settings.POSTGRES_REPLICA_CONNECT_TIMEOUT,
        },
    )


class RoutingSession(Session):
    _force_master: bool = False

    @property
    def force_master(self) -> bool:
        return self._force_master

    def set_force_master(self, value: bool) -> None:
        self._force_master = value

    def get_bind(self, mapper=None, clause=None) -> Engine:  # type: ignore  # noqa: ARG002
        logger.critical("-- CALL RoutingSession.get_bind --")

        if isinstance(clause, Update | Insert | Delete):
            logger.critical("MASTER")
            return engines["master"].sync_engine

        if self._force_master or self._flushing:
            logger.critical("MASTER")
            return engines["master"].sync_engine
        else:
            logger.critical("REPLICA")
            return engines["replica"].sync_engine

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
