"""UDP server for CLDAP protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import ip_address
from traceback import format_exc

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
    filter=lambda rec: rec["extra"].get("name") == "cldap",
    retention="10 days",
    rotation="1d",
    colorize=False,
)


class CLDAPUDPServer:
    """UDP ldap server."""

    def __init__(self, settings: Settings, container: AsyncContainer):
        """Initialize UDP server."""
        self._settings = settings
        self._container = container
        self._logger = DataLogger(log, is_full=self._settings.DEBUG)

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

        try:
            session = await container.get(AsyncSession)
            await ldap_session.validate_conn(ldap_session.ip, session)
        except PermissionError:
            log.warning(f"Whitelist violation from UDP {addr_str}")
            raise ConnectionAbortedError

        log.info(f"UDP datagram received from {addr_str}")

        try:
            request = LDAPRequestMessage.from_bytes(data)
            self._logger.req_log(addr_str, request)

        except (
            ValidationError,
            IndexError,
            KeyError,
            ValueError,
        ) as err:
            log.trace(f"Invalid LDAP schema from {addr_str}")
            return LDAPRequestMessage.from_err(data, err).encode()

        handler = request.context.handle_udp(container)
        responses = [
            response async for response in request.create_response(handler)
        ]
        for response in responses:
            self._logger.rsp_log(addr_str, response)

        return b"".join(response.encode() for response in responses)

    async def start(self) -> None:
        """Start UDP server for CLDAP protocol."""
        sock = await create_udp_socket(
            local_addr=(str(self._settings.HOST), self._settings.PORT),
        )

        mode = "DEBUG" if self._settings.DEBUG else "PROD"
        log.info(f"started {mode} CLDAP server")

        try:
            while True:
                packet = await sock.recvfrom()

                async with self._container(scope=Scope.REQUEST) as container:
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
            log.critical(f"Error in cldap: {err}")
            log.error(f"UDP handler traceback failed: {format_exc()}")
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Stop UDP server gracefully."""
        log.info("Stopping CLDAP server...")

        if self._container:
            await self._container.close()

        log.info("CLDAP server stopped")
