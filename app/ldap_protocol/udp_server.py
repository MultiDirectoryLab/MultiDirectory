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

log = logger.bind(name="cldap")
log.add(
    "logs/cldap_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == "ldap",
    retention="10 days",
    rotation="1d",
    colorize=False,
)


class UDPConnectionHandler(asyncio.DatagramProtocol):
    """UDP server for CLDAP protocol with improved architecture."""

    def __init__(self, settings: Settings, container: AsyncContainer):
        """Initialize UDP server."""
        self.settings = settings
        self.container = container
        self.logger = DataLogger(log, full=self.settings.DEBUG)
        self.transport: asyncio.DatagramTransport | None = None
        self._running = asyncio.Event()
        self._server_task: asyncio.Task | None = None

    async def _handle_datagram(
        self,
        data: bytes,
        addr: tuple[str, int],
    ) -> None:
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
                        return

                log.debug(f"UDP datagram received from {addr_str}: {data!r}")

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
                    if self.transport:
                        self.transport.sendto(error_response.encode(), addr)
                    return

                # Handle request
                async with session_scope(scope=Scope.REQUEST) as request_scope:
                    handler = request.context.handle_tcp(request_scope)

                    async for response in request.create_response(handler):
                        self.logger.rsp_log(addr_str, response)

                        if self.transport and not self.transport.is_closing():
                            response_data = response.encode()
                            self.transport.sendto(response_data, addr)
                        break  # CLDAP typically expects single response

        except asyncio.CancelledError:
            log.debug(f"UDP handler cancelled for {addr_str}")
            raise
        except Exception as err:
            log.error(f"UDP handler error for {addr_str}: {err}")
            log.debug(f"UDP handler traceback: {format_exc()}")

    async def _datagram_handler(
        self,
        data: bytes,
        addr: tuple[str, int],
    ) -> None:
        """Wrap for datagram handling with task management."""
        try:
            await self._handle_datagram(data, addr)
        except Exception as err:
            log.error(f"Unhandled error in UDP datagram handler: {err}")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Call when a datagram is received."""
        if not self._running.is_set():
            return

        # Create task for handling datagram
        loop = asyncio.get_running_loop()
        task = loop.create_task(self._datagram_handler(data, addr))

        # Add error handling for the task
        def task_done_callback(task: asyncio.Task) -> None:
            if task.exception():
                log.error(f"UDP task failed: {task.exception()}")

        task.add_done_callback(task_done_callback)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Call when connection is established."""
        if not isinstance(transport, asyncio.DatagramTransport):
            raise TypeError("Expected DatagramTransport")

        self.transport = transport
        self._running.set()
        log.debug("UDP connection established")

    def connection_lost(self, exc: Exception | None) -> None:
        """Call when connection is lost."""
        self._running.clear()
        log.debug(f"UDP connection lost: {exc}")

    def error_received(self, exc: Exception) -> None:
        """Call when an error is received."""
        log.error(f"UDP error received: {exc}")

    async def start_server(self) -> None:
        """Start UDP server for CLDAP protocol."""
        if self._running.is_set():
            log.warning("UDP server already running")
            return

        try:
            loop = asyncio.get_running_loop()
            log.info("Starting CLDAP server...")

            transport, _ = await loop.create_datagram_endpoint(
                lambda: self,
                local_addr=(str(self.settings.HOST), self.settings.PORT),
                reuse_port=True,
            )

            self.transport = transport

            log.success(
                f"CLDAP server started on "
                f"{self.settings.HOST}:{self.settings.PORT}",
            )

            try:
                await self._running.wait()
            except asyncio.CancelledError:
                log.info("CLDAP server shutdown requested")
            finally:
                await self.stop_server()

        except Exception as err:
            log.error(f"Failed to start CLDAP server: {err}")
            raise

    async def stop_server(self) -> None:
        """Stop UDP server gracefully."""
        if not self._running.is_set():
            return

        log.info("Stopping CLDAP server...")
        self._running.clear()

        if self.transport and not self.transport.is_closing():
            self.transport.close()

        # Wait a bit for cleanup
        await asyncio.sleep(0.1)

        if self.container:
            await self.container.close()

        log.info("CLDAP server stopped")

    def __del__(self) -> None:
        """Cleanup on deletion."""
        if self.transport and not self.transport.is_closing():
            self.transport.close()
