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


async def proc_time_header_middleware(
    request: Request,
    call_next: Callable,
) -> Response:
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


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    await app.state.dishka_container.close()


def _create_basic_app(settings: Settings) -> FastAPI:
    """Create basic FastAPI app with dependencies overrides."""
    app = FastAPI(
        name="MultiDirectory",
        title="MultiDirectory",
        debug=settings.DEBUG,
        root_path="/api",
        version=settings.VENDOR_VERSION,
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
    app.include_router(session_router)
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

    app.add_exception_handler(sa_exc.TimeoutError, handle_db_connect_error)
    app.add_exception_handler(sa_exc.InterfaceError, handle_db_connect_error)
    app.add_exception_handler(DNSException, handle_dns_error)
    app.add_exception_handler(DNSConnectionError, handle_dns_error)
    return app


def _create_shadow_app(settings: Settings) -> FastAPI:
    """Create shadow FastAPI app for shadow."""
    app = FastAPI(
        name="Shadow API",
        title="Internal API",
        debug=settings.DEBUG,
        version=settings.VENDOR_VERSION,
        lifespan=_lifespan,
    )
    app.include_router(shadow_router)
    return app


def create_prod_app(
    factory: Callable[[Settings], FastAPI] = _create_basic_app,
    settings: Settings | None = None,
) -> FastAPI:
    """Create production app with container."""
    settings = settings or Settings()
    app = factory(settings)
    container = make_async_container(
        MainProvider(),
        MFAProvider(),
        HTTPProvider(),
        MFACredsProvider(),
        context={Settings: settings},
    )

    setup_dishka(container, app)
    return app


create_shadow_app = partial(create_prod_app, factory=_create_shadow_app)


def ldap(settings: Settings) -> None:
    """Run server."""

    async def _servers(settings: Settings) -> None:
        servers = []

        for setting in (settings, settings.get_copy_4_tls()):
            container = make_async_container(
                LDAPServerProvider(),
                MainProvider(),
                MFAProvider(),
                MFACredsProvider(),
                context={Settings: setting},
            )

            settings = await container.get(Settings)
            servers.append(PoolClientHandler(settings, container).start())

        await asyncio.gather(*servers)

    def _run() -> None:
        uvloop.run(_servers(settings), debug=settings.DEBUG)

    try:
        import py_hot_reload
    except ImportError:
        _run()
    else:
        if settings.DEBUG:
            py_hot_reload.run_with_reloader(_run)
        else:
            _run()


if __name__ == "__main__":
    settings = Settings()

    parser = argparse.ArgumentParser(description="Run ldap or http")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--ldap', action='store_true', help="Run ldap")
    group.add_argument('--http', action='store_true', help="Run http")
    group.add_argument('--shadow', action='store_true', help="Run http")
    group.add_argument('--scheduler', action='store_true', help="Run tasks")

    args = parser.parse_args()

    if args.ldap:
        ldap(settings)

    elif args.shadow:
        uvicorn.run(
            "__main__:create_shadow_app",
            host=str(settings.HOST),
            port=settings.HTTP_PORT,
            reload=settings.DEBUG,
            loop="uvloop",
            factory=True,
        )

    elif args.http:
        uvicorn.run(
            "__main__:create_prod_app",
            host=str(settings.HOST),
            port=settings.HTTP_PORT,
            reload=settings.DEBUG,
            loop="uvloop",
            factory=True,
        )
    elif args.scheduler:
        scheduler(settings)
