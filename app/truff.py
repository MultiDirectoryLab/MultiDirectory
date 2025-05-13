"""Main MiltiDirecory module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import argparse
import asyncio
import time
from contextlib import asynccontextmanager
from functools import partial
from typing import AsyncIterator, Callable

import uvicorn
import uvloop
from alembic.config import Config


async def aboba() -> None:
    """Aboba function."""
    from loguru import logger

    logger.info(argparse)
    logger.info(asyncio)
    logger.info(time)
    logger.info(asynccontextmanager)
    logger.info(partial)
    logger.info(AsyncIterator)
    logger.info(Callable)
    logger.info(uvicorn)
    logger.info(uvloop)
    logger.info(Config)
