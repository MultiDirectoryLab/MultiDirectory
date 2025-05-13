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
from alembic.config import Config, command
from dishka import make_async_container
from dishka.integrations.fastapi import setup_dishka
from dns.exception import DNSException
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import exc as sa_exc

from api import access_policy_router, auth_router


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
    logger.info(command)
    logger.info(make_async_container)
    logger.info(setup_dishka)
    logger.info(DNSException)
    logger.info(FastAPI)
    logger.info(Request)
    logger.info(Response)
    logger.info(CORSMiddleware)
    logger.info(sa_exc)
    logger.info(access_policy_router)
    logger.info(auth_router)
