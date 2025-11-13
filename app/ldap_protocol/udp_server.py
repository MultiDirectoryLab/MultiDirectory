"""UDP server for CLDAP protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import ip_address

from dishka import AsyncContainer, Scope
from loguru import logger
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol import LDAPRequestMessage, LDAPSession

from .data_logger import DataLogger
from .utils.udp import create_udp_socket

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
        container: AsyncContainer,
    ) -> bytes:
        """Handle individual datagram with proper error handling."""
        addr_str = f"{addr[0]}:{addr[1]}"

        ldap_session = await container.get(LDAPSession)
        ldap_session.ip = ip_address(addr[0])

        # Validate connection if needed
        try:
            session = await container.get(AsyncSession)
            await ldap_session.validate_conn(ldap_session.ip, session)
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
            log.trace(f"Invalid LDAP schema from {addr_str}")

            return LDAPRequestMessage.from_err(data, err).encode()

        # Handle request
        handler = request.context.handle_udp(container)
        return b"".join(
            [
                response.encode()
                async for response in request.create_response(handler)
            ],
        )

    async def start(self) -> None:
        """Start UDP server for CLDAP protocol."""
        sock = await create_udp_socket(
            local_addr=(str(self.settings.HOST), self.settings.PORT),
        )

        stype = "DEBUG" if self.settings.DEBUG else "PROD"
        log.info(f"started {stype} CLDAP server")

        try:
            while True:
                packet = await sock.recvfrom()

                async with self.container(scope=Scope.REQUEST) as container:
                    try:
                        response = await self._handle(
                            packet.data,
                            packet.addr,
                            container,
                        )
                    except ConnectionAbortedError:
                        continue
                    else:
                        sock.sendto(response, packet.addr)

        except Exception as err:
            log.critical(err)
            log.trace("UDP handler traceback failed")
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Stop UDP server gracefully."""
        log.info("Stopping CLDAP server...")

        if self.container:
            await self.container.close()

        log.info("CLDAP server stopped")
