"""Main MultiDirecory module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import argparse
import asyncio
from contextlib import asynccontextmanager
from functools import partial
from typing import AsyncIterator, Callable, Coroutine

import uvicorn
import uvloop
from alembic.config import Config, command
from dishka import Scope, make_async_container
from dishka.integrations.fastapi import setup_dishka
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from sqlalchemy import exc as sa_exc

from api import (
    audit_router,
    auth_router,
    dhcp_router,
    dns_router,
    entry_router,
    krb5_router,
    ldap_schema_router,
    mfa_router,
    network_router,
    password_ban_word_router,
    password_policy_router,
    session_router,
    shadow_router,
)
from api.exception_handlers import handle_auth_error, handle_db_connect_error
from api.middlewares import proc_time_header_middleware, set_key_middleware
from config import Settings
from extra.dump_acme_certs import dump_acme_cert
from ioc import (
    EventSenderProvider,
    HTTPProvider,
    LDAPServerProvider,
    MainProvider,
    MFACredsProvider,
    MFAProvider,
)
from ldap_protocol.dependency import resolve_deps
from ldap_protocol.identity.exceptions import IdentityUnauthorizedError
from ldap_protocol.policies.audit.events.handler import AuditEventHandler
from ldap_protocol.policies.audit.events.sender import AuditEventSenderManager
from ldap_protocol.server import PoolClientHandler
from ldap_protocol.udp_server import CLDAPUDPServer
from schedule import scheduler_factory


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
    app.include_router(audit_router)
    app.include_router(auth_router)
    app.include_router(entry_router)
    app.include_router(network_router)
    app.include_router(mfa_router)
    app.include_router(password_ban_word_router)
    app.include_router(password_policy_router)
    app.include_router(krb5_router)
    app.include_router(dns_router)
    app.include_router(session_router)
    app.include_router(ldap_schema_router)
    app.include_router(dhcp_router)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    if settings.DEBUG:
        app.middleware("http")(proc_time_header_middleware)

    app.middleware("http")(set_key_middleware)
    app.add_exception_handler(sa_exc.TimeoutError, handle_db_connect_error)
    app.add_exception_handler(sa_exc.InterfaceError, handle_db_connect_error)
    app.add_exception_handler(IdentityUnauthorizedError, handle_auth_error)
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


def _add_app_sqlalchemy_debugger(app: FastAPI, settings: Settings) -> None:
    try:
        import json
        from dataclasses import asdict

        from fastapi_sqlalchemy_monitor import SQLAlchemyMonitor
        from fastapi_sqlalchemy_monitor.action import Action
        from fastapi_sqlalchemy_monitor.statistics import AlchemyStatistics
    except ImportError:
        pass
    else:

        class JsonPrintStatistics(Action):
            """Action that prints current statistics."""

            def handle(self, statistics: AlchemyStatistics) -> None:
                logger.debug(str(statistics), json.dumps(asdict(statistics)))

        app.add_middleware(
            SQLAlchemyMonitor,
            engine=settings.engine,
            actions=[JsonPrintStatistics()],
        )


def create_prod_app(
    factory: Callable[[Settings], FastAPI] = _create_basic_app,
    settings: Settings | None = None,
) -> FastAPI:
    """Create production app with container."""
    settings = settings or Settings.from_os()
    app = factory(settings)
    container = make_async_container(
        MainProvider(),
        MFAProvider(),
        HTTPProvider(),
        MFACredsProvider(),
        context={Settings: settings},
    )

    if settings.ENABLE_SQLALCHEMY_LOGGING:
        _add_app_sqlalchemy_debugger(app, settings)

    setup_dishka(container, app)
    return app


def run_entrypoint(
    factory: Callable[[Settings], Coroutine],
    settings: Settings,
) -> None:
    """Run server."""

    def _run() -> None:
        uvloop.run(factory(settings), debug=settings.DEBUG)

    try:
        import py_hot_reload
    except ImportError:
        _run()
    else:
        if settings.DEBUG:
            py_hot_reload.run_with_reloader(_run)
        else:
            _run()


async def ldap_factory(settings: Settings) -> None:
    """Run LDAP server factory."""
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


async def cldap_factory(settings: Settings) -> None:
    """Run CLDAP server factory."""
    container = make_async_container(
        LDAPServerProvider(),
        MainProvider(),
        MFAProvider(),
        MFACredsProvider(),
        context={Settings: settings},
    )

    await CLDAPUDPServer(settings, container).start()


async def event_handler_factory(settings: Settings) -> None:
    """Run event handler."""
    main_container = make_async_container(
        MainProvider(),
        context={Settings: settings},
    )

    async with main_container(scope=Scope.REQUEST) as container:
        kwargs = await resolve_deps(
            AuditEventHandler.__init__,
            container=container,
        )
        await asyncio.gather(AuditEventHandler(**kwargs).run())


async def event_sender_factory(settings: Settings) -> None:
    """Run event sender."""
    main_container = make_async_container(
        MainProvider(),
        EventSenderProvider(),
        context={Settings: settings},
    )

    async with main_container(scope=Scope.REQUEST) as container:
        manager = await container.get(AuditEventSenderManager)
        await asyncio.gather(manager.run())


ldap = partial(run_entrypoint, factory=ldap_factory)
cldap = partial(run_entrypoint, factory=cldap_factory)
scheduler = partial(run_entrypoint, factory=scheduler_factory)
create_shadow_app = partial(create_prod_app, factory=_create_shadow_app)
event_handler = partial(run_entrypoint, factory=event_handler_factory)
event_sender = partial(run_entrypoint, factory=event_sender_factory)


if __name__ == "__main__":
    settings = Settings.from_os()

    parser = argparse.ArgumentParser(description="Run ldap or http")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ldap", action="store_true", help="Run ldap")
    group.add_argument("--cldap", action="store_true", help="Run cldap")
    group.add_argument("--http", action="store_true", help="Run http")
    group.add_argument("--shadow", action="store_true", help="Run http")
    group.add_argument("--scheduler", action="store_true", help="Run tasks")
    group.add_argument(
        "--event_handler",
        action="store_true",
        help="Run event handler",
    )
    group.add_argument(
        "--event_sender",
        action="store_true",
        help="Run event sender",
    )
    group.add_argument(
        "--certs_dumper",
        action="store_true",
        help="Dump certs",
    )
    group.add_argument(
        "--migrate",
        action="store_true",
        help="Make migrations",
    )

    args = parser.parse_args()

    if args.ldap:
        ldap(settings=settings)

    if args.cldap:
        cldap(settings=settings)

    elif args.event_sender:
        event_sender(settings=settings)

    elif args.shadow:
        uvicorn.run(
            "__main__:create_shadow_app",
            host=str(settings.HOST),
            port=settings.HTTP_PORT,
            reload=settings.AUTO_RELOAD,
            loop="uvloop",
            factory=True,
        )

    elif args.http:
        uvicorn.run(
            "__main__:create_prod_app",
            host=str(settings.HOST),
            port=settings.HTTP_PORT,
            reload=settings.AUTO_RELOAD,
            loop="uvloop",
            factory=True,
        )
    elif args.scheduler:
        scheduler(settings=settings)
    elif args.event_handler:
        event_handler(settings=settings)
    elif args.certs_dumper:
        dump_acme_cert()
    elif args.migrate:
        command.upgrade(Config("alembic.ini"), "head")
