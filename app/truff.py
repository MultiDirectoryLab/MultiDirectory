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

from api import (
    access_policy_router,
    auth_router,
    dns_router,
    entry_router,
    krb5_router,
    mfa_router,
    network_router,
    pwd_router,
    session_router,
    shadow_router,
)
from api.exception_handlers import handle_db_connect_error, handle_dns_error
from config import Settings
from extra.dump_acme_certs import dump_acme_cert
from ioc import (
    HTTPProvider,
    LDAPServerProvider,
    MainProvider,
    MFACredsProvider,
    MFAProvider,
)
from ldap_protocol.dns import DNSConnectionError
from ldap_protocol.server import PoolClientHandler
from schedule import scheduler


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
    logger.info(dns_router)
    logger.info(entry_router)
    logger.info(krb5_router)
    logger.info(mfa_router)
    logger.info(network_router)
    logger.info(pwd_router)
    logger.info(session_router)
    logger.info(shadow_router)
    logger.info(handle_db_connect_error)
    logger.info(handle_dns_error)
    logger.info(Settings)
    logger.info(dump_acme_cert)
    logger.info(HTTPProvider)
    logger.info(LDAPServerProvider)
    logger.info(MainProvider)
    logger.info(MFACredsProvider)
    logger.info(MFAProvider)
    logger.info(DNSConnectionError)
    logger.info(PoolClientHandler)
    logger.info(scheduler)
