"""UDP server for CLDAP protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from ipaddress import ip_address
from traceback import format_exc

from dishka import AsyncContainer, Scope
from loguru import logger
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol import LDAPRequestMessage, LDAPSession

from .data_logger import DataLogger
from .udp import create_udp_socket

log = logger.bind(name="cldap")
log.add(
    "logs/cldap_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == "ldap",
    retention="10 days",
    rotation="1d",
    colorize=False,
)


class CLDAPUDPServer:
    """UDP ldap server."""

    def __init__(self, settings: Settings, container: AsyncContainer):
        """Initialize UDP server."""
        self.settings = settings
        self.container = container
        self.logger = DataLogger(log, full=self.settings.DEBUG)

    async def _handle(
        self,
        data: bytes,
        addr: tuple[str, int],
    ) -> bytes:
        """Handle individual datagram with proper error handling."""
        addr_str = f"{addr[0]}:{addr[1]}"

        try:
            async with self.container(scope=Scope.SESSION) as session_scope:
                ldap_session = await session_scope.get(LDAPSession)
                ldap_session.ip = ip_address(addr[0])

                # Validate connection if needed
                async with session_scope(scope=Scope.REQUEST) as request_scope:
                    try:
                        session = await request_scope.get(AsyncSession)
                        await ldap_session.validate_conn(
                            ldap_session.ip,
                            session,
                        )
                    except PermissionError:
                        log.warning(f"Whitelist violation from UDP {addr_str}")
                        raise ConnectionAbortedError

                log.info(f"UDP datagram received from {addr_str}")

                try:
                    request = LDAPRequestMessage.from_bytes(data)
                    self.logger.req_log(addr_str, request)

                except (
                    ValidationError,
                    IndexError,
                    KeyError,
                    ValueError,
                ) as err:
                    log.error(
                        f"Invalid UDP schema from {addr_str}: {format_exc()}",
                    )

                    error_response = LDAPRequestMessage.from_err(data, err)
                    return error_response.encode()

                # Handle request
                async with session_scope(scope=Scope.REQUEST) as request_scope:
                    handler = request.context.handle_tcp(request_scope)

                    async for response in request.create_response(handler):
                        self.logger.rsp_log(addr_str, response)
                        # CLDAP typically expects single response
                        return response.encode()

        except asyncio.CancelledError:
            log.debug(f"UDP handler cancelled for {addr_str}")
            raise
        except Exception as err:
            log.error(f"UDP handler error for {addr_str}: {err}")
            log.debug(f"UDP handler traceback: {format_exc()}")

        raise

    async def start(self) -> None:
        """Start UDP server for CLDAP protocol."""
        sock = await create_udp_socket(
            local_addr=(str(self.settings.HOST), self.settings.PORT),
        )
        log.info("started DEBUG CLDAP server")
        try:
            while True:
                p = await sock.recvfrom()
                d = await self._handle(p.data, p.addr)
                sock.sendto(d, p.addr)
        except Exception as err:
            log.critical(err)
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Stop UDP server gracefully."""
        log.info("Stopping CLDAP server...")

        if self.container:
            await self.container.close()

        log.info("CLDAP server stopped")
