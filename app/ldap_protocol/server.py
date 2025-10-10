"""LDAP tcp server.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import math
import ssl
from contextlib import suppress
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address, ip_address
from traceback import format_exc
from typing import Literal, cast, overload

from dishka import AsyncContainer, Scope
from loguru import logger
from proxyprotocol import ProxyProtocolIncompleteError
from proxyprotocol.v2 import ProxyProtocolV2
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol import LDAPRequestMessage, LDAPSession
from ldap_protocol.ldap_requests.bind_methods import GSSAPISL
from ldap_protocol.messages import LDAPMessage, LDAPResponseMessage

log = logger.bind(name="ldap")


log.add(
    "logs/ldap_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == "ldap",
    retention="10 days",
    rotation="1d",
    colorize=False,
)


infinity = cast("int", math.inf)
pp_v2 = ProxyProtocolV2()


class PoolClientHandler:
    """Async client handler.

    Don't need to wait until client sends
    request or do not need to wait until response formed.
    Can handle requests for a single client asynchronously.

    No __init__ method, as `start_server`
    uses callable object for a single connection.
    """

    ssl_context: ssl.SSLContext | None = None

    def __init__(self, settings: Settings, container: AsyncContainer):
        """Set workers number for single client concurrent handling."""
        self.container = container
        self.settings = settings

        self.num_workers = self.settings.COROUTINES_NUM_PER_CLIENT
        self._size = self.settings.TCP_PACKET_SIZE

        self._load_ssl_context()

        if settings.DEBUG:
            self.req_log = self._req_log_full
            self.rsp_log = self._resp_log_full
        else:
            self.req_log = self.rsp_log = self._log_short

    async def __call__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Create session, queue and start message handlers concurrently."""
        async with self.container(scope=Scope.SESSION) as session_scope:
            ldap_session = await session_scope.get(LDAPSession)
            addr, first_chunk = await self.recieve(
                reader,
                writer,
                return_addr=True,
            )
            ldap_session.ip = addr

            logger.info(f"Connection {addr} opened")

            try:
                async with session_scope(scope=Scope.REQUEST) as r:
                    try:
                        session = await r.get(AsyncSession)
                        await ldap_session.validate_conn(addr, session)
                    except PermissionError:
                        log.warning(f"Whitelist violation from {addr}")
                        return

                async with asyncio.TaskGroup() as tg:
                    tg.create_task(
                        self._handle_request(
                            first_chunk,
                            reader,
                            writer,
                            session_scope,
                        ),
                    )
                    tg.create_task(
                        self._handle_responses(writer, session_scope),
                    )
                    ensure_task = tg.create_task(
                        ldap_session.ensure_session_exists(
                            self.settings.LDAP_SESSION_CHECK_INTERVAL,
                        ),
                    )
                    tg.create_task(
                        ldap_session.cancel_ensure_task(ensure_task),
                    )

            except* RuntimeError:
                log.exception(f"The connection {addr} raised")

            finally:
                await session_scope.close()

                with suppress(RuntimeError):
                    writer.close()
                    await writer.wait_closed()

                logger.info(f"Connection {addr} closed")

    def _load_ssl_context(self) -> None:
        """Load SSL context for LDAPS."""
        if self.settings.USE_CORE_TLS and self.settings.LDAP_LOAD_SSL_CERT:
            if not self.settings.check_certs_exist():
                log.critical("Certs not found, exiting...")
                raise SystemExit(1)

            cert_name = self.settings.SSL_CERT
            key_name = self.settings.SSL_KEY
            log.success("Found existing cert and key, loading...")
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            self.ssl_context.load_cert_chain(cert_name, key_name)

    def _extract_proxy_protocol_address(
        self,
        data: bytes,
        writer: asyncio.StreamWriter,
    ) -> tuple[IPv4Address | IPv6Address, bytes]:
        """Get ip from proxy protocol header.

        :param bytes data: data
        :return tuple: ip, data
        """
        peername = ":".join(map(str, writer.get_extra_info("peername")))
        peer_addr = ip_address(peername.split(":")[0])

        try:
            if not pp_v2.is_valid(data[0:8]):
                return peer_addr, data

            result = pp_v2.unpack(data)
            if not isinstance(result.source, tuple):
                raise ValueError("Invalid source address")

            addr = result.source[0]
            header_length = int.from_bytes(data[14:16], "big")
            return addr, data[16 + header_length :]
        except (ValueError, ProxyProtocolIncompleteError) as err:
            log.error(f"Proxy Protocol processing error: {err}")
            return peer_addr, data

    @overload
    async def recieve(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        return_addr: Literal[True],
    ) -> tuple[IPv4Address | IPv6Address, bytes]: ...

    @overload
    async def recieve(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        return_addr: Literal[False] = False,
    ) -> bytes: ...

    async def recieve(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        return_addr: Literal[True, False] | bool = False,
    ) -> tuple[IPv4Address | IPv6Address, bytes] | bytes:
        """Read N packets by 1kB.

        :param asyncio.StreamReader reader: reader
        :return tuple: ip, data
        """
        buffer = BytesIO()
        addr = None

        while True:
            data = await reader.read(self._size)

            if return_addr and not addr:
                addr, data = self._extract_proxy_protocol_address(data, writer)

            buffer.write(data)
            actual_size = buffer.getbuffer().nbytes
            computed_size = self._compute_ldap_message_size(buffer.getvalue())

            if reader.at_eof() or actual_size >= computed_size:
                break

        if not return_addr or not addr:
            return buffer.getvalue()

        return addr, buffer.getvalue()

    @staticmethod
    def _compute_ldap_message_size(data: bytes) -> int:
        """Compute LDAP Message size according to BER definite length rules.

        returns infinity if too few data to compute message length.

        BER definite length - short form.
        Highest bit of byte 1 is 0, message length is in the last 7 bits -
            Value can be up to 127 bytes long

        BER definite length - long form.
        Highest bit of byte 1 is 1, last 7 bits
        counts the number of following octets containing the value length.

        source:
        https://github.com/cannatag/ldap3/blob/dev/ldap3/strategy/base.py#L455

        :param bytes data: body
        :return int: actual size
        """
        if len(data) > 2:
            if data[1] <= 127:  # short
                return data[1] + 2

            bytes_length = data[1] - 128  # long
            if len(data) >= bytes_length + 2:
                value_length = 0
                cont = bytes_length
                for byte in data[2 : 2 + bytes_length]:
                    cont -= 1
                    value_length += byte * (256**cont)
                return value_length + 2 + bytes_length
        return infinity

    async def _handle_request(
        self,
        data: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        container: AsyncContainer,
    ) -> None:
        """Create request object and send it to queue.

        :param bytes data: initial data
        :param asyncio.StreamReader reader: reader
        :param asyncio.StreamWriter writer: writer
        :param AsyncContainer container: container
        :raises RuntimeError: reraises on unexpected exc
        """
        ldap_session: LDAPSession = await container.get(LDAPSession)
        while ldap_session.session_active.is_set():
            if not data:
                ldap_session.session_active.clear()
                return

            if ldap_session.gssapi_authenticated:
                data = await self._unwrap_request(data, ldap_session)

            try:
                request = LDAPRequestMessage.from_bytes(data)

            except (ValidationError, IndexError, KeyError, ValueError) as err:
                log.error(f"Invalid schema {format_exc()}")

                writer.write(LDAPRequestMessage.from_err(data, err).encode())
                await writer.drain()

            except Exception as err:
                raise RuntimeError(err) from err

            else:
                await ldap_session.queue.put(request)

            data = await self.recieve(reader, writer)

    async def _unwrap_request(
        self,
        data: bytes,
        ldap_session: LDAPSession,
    ) -> bytes:
        """Unwrap request with GSSAPI security layer if needed.

        :param bytes data: request data
        :param LDAPSession ldap_session: session
        :return bytes: unwrapped data
        """
        if ldap_session.gssapi_security_layer in (
            GSSAPISL.INTEGRITY_PROTECTION,
            GSSAPISL.CONFIDENTIALITY,
        ):
            sasl_buffer_length = int.from_bytes(data[:4], "big")
            sasl_buffer = data[4:]

            if len(sasl_buffer) != sasl_buffer_length:
                raise ConnectionAbortedError(
                    "SASL buffer length mismatch",
                )

            if not ldap_session.gssapi_security_context:
                raise ConnectionAbortedError(
                    "GSSAPI security context not found",
                )

            unwrap_data = ldap_session.gssapi_security_context.unwrap(
                sasl_buffer,
            )
            message = unwrap_data.message
            data = message
            return data

        return data

    @staticmethod
    def _req_log_full(addr: str, msg: LDAPRequestMessage) -> None:
        log.debug(
            f"\nFrom: {addr!r}\n{msg.name}[{msg.message_id}]: "
            f"{msg.model_dump_json()}\n",
        )

    @staticmethod
    def _resp_log_full(addr: str, msg: LDAPResponseMessage) -> None:
        log.debug(
            f"\nTo: {addr!r}\n{msg.name}[{msg.message_id}]: "
            f"{msg.model_dump_json()}"[:3000],
        )

    @staticmethod
    def _log_short(addr: str, msg: LDAPMessage) -> None:
        log.info(f"\n{addr!r}: {msg.name}[{msg.message_id}]\n")

    async def _handle_single_response(
        self,
        writer: asyncio.StreamWriter,
        container: AsyncContainer,
    ) -> None:
        """Get message from queue and handle it."""
        ldap_session: LDAPSession = await container.get(LDAPSession)
        addr = str(ldap_session.ip)

        while (
            ldap_session.session_active.is_set()
            or not ldap_session.queue.empty()
        ):
            try:
                message = await asyncio.wait_for(
                    ldap_session.queue.get(),
                    timeout=1.0,
                )
                self.req_log(addr, message)

                async with container(scope=Scope.REQUEST) as request_container:
                    handler = message.context.handle_tcp(request_container)

                    async for response in message.create_response(handler):
                        self.rsp_log(addr, response)

                        data = await self._wrap_response(
                            response.encode(),
                            ldap_session,
                            response.context.PROTOCOL_OP,
                        )

                        writer.write(data)
                        await writer.drain()

                ldap_session.queue.task_done()
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                with suppress(ValueError):
                    ldap_session.queue.task_done()
                raise
            except Exception as err:
                with suppress(ValueError):
                    ldap_session.queue.task_done()
                raise RuntimeError(err) from err

    async def _wrap_response(
        self,
        data: bytes,
        ldap_session: LDAPSession,
        protocol_op: int,
    ) -> bytes:
        """Wrap response with GSSAPI security layer if needed.

        :param bytes data: response data
        :param LDAPSession ldap_session: session
        :param int protocol_op: protocol operation
        :return bytes: wrapped data
        """
        if (
            ldap_session.gssapi_authenticated
            and protocol_op != 1
            and ldap_session.gssapi_security_context
        ) and ldap_session.gssapi_security_layer in (
            GSSAPISL.INTEGRITY_PROTECTION,
            GSSAPISL.CONFIDENTIALITY,
        ):
            encrypt = ldap_session.gssapi_security_layer == (
                GSSAPISL.CONFIDENTIALITY
            )
            wrap_data = ldap_session.gssapi_security_context.wrap(
                data,
                encrypt=encrypt,
            )
            sasl_buffer_length = len(wrap_data.message).to_bytes(4, "big")

            return sasl_buffer_length + wrap_data.message

        return data

    async def _handle_responses(
        self,
        writer: asyncio.StreamWriter,
        container: AsyncContainer,
    ) -> None:
        """Create pool of workers and apply handler to it.

        Spawns (default 5) workers,
        then every task awaits for queue object,
        cycle locks until pool completes at least 1 task.
        """
        async with asyncio.TaskGroup() as tg:
            for _ in range(self.num_workers):
                tg.create_task(self._handle_single_response(writer, container))

    async def _get_server(self) -> asyncio.base_events.Server:
        """Get async server."""
        return await asyncio.start_server(
            self,
            str(self.settings.HOST),
            self.settings.PORT,
            ssl=self.ssl_context,
        )

    @staticmethod
    async def _run_server(server: asyncio.base_events.Server) -> None:
        """Run server."""
        async with server:
            await server.serve_forever()

    @staticmethod
    def log_addrs(server: asyncio.base_events.Server) -> None:
        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        log.info(f"Server on {addrs}")

    async def start(self) -> None:
        """Run and log tcp server."""
        server = await self._get_server()
        log.info(
            f"started {'DEBUG' if self.settings.DEBUG else 'PROD'} "
            f"{'LDAPS' if self.settings.USE_CORE_TLS else 'LDAP'} server",
        )

        try:
            await self._run_server(server)
        finally:
            server.close()
            await server.wait_closed()
            await self.container.close()
