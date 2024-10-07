"""Multidirectory api module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import time
from contextlib import asynccontextmanager
from typing import AsyncIterator, Callable

import dns.exception
from dishka import make_async_container
from dishka.integrations.fastapi import setup_dishka
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import exc

from api import (
    access_policy_router,
    auth_router,
    dns_router,
    entry_router,
    krb5_router,
    mfa_router,
    network_router,
    pwd_router,
)
from api.exception_handlers import handle_db_connect_error, handle_dns_error
from config import VENDOR_VERSION, Settings
from ioc import HTTPProvider, MainProvider, MFACredsProvider, MFAProvider


async def proc_time_header_middleware(
        request: Request, call_next: Callable) -> Response:
    """Set X-Process-Time header.

    :param Request request: _description_
    :param Callable call_next: _description_
    :return Response: _description_
    """
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start_time
    response.headers["X-Process-Time"] = "{:.4f}".format(process_time)
    return response


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create FastAPI app with dependencies overrides."""
    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        await app.state.dishka_container.close()

    settings = settings or Settings()

    app = FastAPI(
        name="MultiDirectory",
        title="MultiDirectory",
        debug=settings.DEBUG,
        root_path="/api",
        version=VENDOR_VERSION,
        lifespan=_lifespan,
    )
    origins = [settings.DOMAIN]
    app.include_router(auth_router)
    app.include_router(entry_router)
    app.include_router(network_router)
    app.include_router(mfa_router)
    app.include_router(pwd_router)
    app.include_router(krb5_router)
    app.include_router(dns_router)
    app.include_router(access_policy_router)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    if settings.DEBUG:
        app.middleware("http")(proc_time_header_middleware)

    app.add_exception_handler(exc.TimeoutError, handle_db_connect_error)
    app.add_exception_handler(exc.InterfaceError, handle_db_connect_error)
    app.add_exception_handler(dns.exception.DNSException, handle_dns_error)
    return app


def create_prod_app() -> FastAPI:
    """Create production app with container."""
    app = create_app()
    container = make_async_container(
        MainProvider(), MFAProvider(),
        HTTPProvider(), MFACredsProvider(),
        context={Settings: Settings()})

    setup_dishka(container, app)
    return app
