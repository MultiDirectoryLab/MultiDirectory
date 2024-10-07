"""Main MiltiDirecory module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio

import uvloop
from dishka import make_async_container

from config import Settings
from ioc import LDAPServerProvider, MainProvider, MFACredsProvider, MFAProvider
from ldap_protocol.server import PoolClientHandler


def main() -> None:
    """Run server."""
    settings = Settings()

    async def _servers(settings: Settings) -> None:
        servers = []

        for setting in (settings, settings.get_copy_4_tls()):
            container = make_async_container(
                LDAPServerProvider(),
                MainProvider(),
                MFAProvider(),
                MFACredsProvider(),
                context={Settings: setting})

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


if __name__ == '__main__':
    main()
