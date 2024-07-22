"""Main MiltiDirecory module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import base64
import json
import math
import os
import socket
import ssl
from contextlib import suppress
from io import BytesIO
from ipaddress import IPv4Address
from tempfile import NamedTemporaryFile
from traceback import format_exc
from typing import cast

import uvloop
from dishka import AsyncContainer, Scope, make_async_container
from loguru import logger
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ioc import LDAPServerProvider, MainProvider, resolve_deps
from ldap_protocol import LDAPRequestMessage, LDAPSession
from ldap_protocol.messages import LDAPMessage, LDAPResponseMessage

log = logger.bind(name='ldap')

log.add(
    "logs/ldap_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == 'ldap',
    retention="10 days",
    rotation="1d",
    colorize=False)


infinity = cast(int, math.inf)


class PoolClientHandler:
    """Async client handler.

    Don't need to wait until client sends
    request or do not need to wait until response formed.
    Can handle requests for a single client asynchronously.

    No __init__ method, as `start_server`
    uses callable object for a single connection.
    """

    def __init__(self, settings: Settings, container: AsyncContainer):
        """Set workers number for single client concurrent handling."""
        self.container = container
        self.settings = settings

        self.num_workers = self.settings.COROUTINES_NUM_PER_CLIENT
        self._size = self.settings.TCP_PACKET_SIZE

        if settings.DEBUG:
            self.req_log = self._req_log_full
            self.rsp_log = self._resp_log_full
        else:
            self.req_log = self.rsp_log = self._log_short

        self.ssl_context = None

        if self.settings.USE_CORE_TLS:
            with (
                NamedTemporaryFile('w+') as certfile,
                NamedTemporaryFile('w+') as keyfile,
            ):
                if os.path.exists('/certs/cert.pem') and os.path.exists(
                        '/certs/privkey.pem'):
                    cert_name = self.settings.SSL_CERT
                    key_name = self.settings.SSL_KEY
                    log.success('Found existing cert and key, loading...')

                else:
                    cert, key = self._read_acme_cert()
                    certfile.write(cert)
                    keyfile.write(key)

                    certfile.seek(0)
                    keyfile.seek(0)

                    cert_name = certfile.name
                    key_name = keyfile.name

                self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                self.ssl_context.load_cert_chain(cert_name, key_name)

    async def __call__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Create session, queue and start message handlers concurrently."""
        async with self.container(
            {asyncio.StreamReader: reader, asyncio.StreamWriter: writer},
            scope=Scope.SESSION,
        ) as session_scope:
            ldap_session = await session_scope.get(LDAPSession)
            addr = await session_scope.get(IPv4Address)

            async with session_scope(scope=Scope.REQUEST) as r:
                try:
                    await ldap_session.validate_conn(
                        addr, await r.get(AsyncSession))
                except PermissionError:
                    log.warning(f"Whitelist violation from {addr}")
                    return

            try:
                await asyncio.gather(
                    self._handle_request(session_scope),
                    self._handle_responses(session_scope),
                )
            except RuntimeError:
                log.exception(f"The connection {addr} raised")
            except ConnectionAbortedError:

                logger.success(f'Connection {addr} closed')
            finally:
                await session_scope.close()
                with suppress(RuntimeError):
                    await ldap_session.queue.join()
                    writer.close()
                    await writer.wait_closed()

    async def recieve(self, reader: asyncio.StreamReader) -> bytes:
        """Read N packets by 1kB."""
        buffer = BytesIO()

        while True:
            buffer.write(await reader.read(self._size))

            actual_size = buffer.getbuffer().nbytes
            computed_size = self._compute_ldap_message_size(buffer.getvalue())

            if reader.at_eof() or actual_size >= computed_size:
                break

        return buffer.getvalue()

    @staticmethod
    def _read_acme_cert() -> tuple[str, str]:
        if not os.path.exists('/certs/acme.json'):
            log.critical('Cannot load SSL cert for MultiDirectory')
            raise

        with open('/certs/acme.json') as certfile:
            data = json.load(certfile)

        try:
            domain = data['md-resolver'][
                'Certificates'][0]['domain']['main']
        except (KeyError, IndexError):
            log.critical('Cannot load SSL cert for MultiDirectory')
            raise

        log.info(f'loaded cert for {domain}')

        cert = data['md-resolver']['Certificates'][0]['certificate']
        key = data['md-resolver']['Certificates'][0]['key']

        cert = base64.b64decode(cert.encode('ascii')).decode()
        key = base64.b64decode(key.encode('ascii')).decode()

        return cert, key

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
                for byte in data[2:2 + bytes_length]:
                    cont -= 1
                    value_length += byte * (256 ** cont)
                return value_length + 2 + bytes_length
        return infinity

    async def _handle_request(self, container: AsyncContainer) -> None:
        """Create request object and send it to queue.

        :raises ConnectionAbortedError: if client sends empty request (b'')
        :raises RuntimeError: reraises on unexpected exc
        """
        reader = await container.get(asyncio.StreamReader)
        writer = await container.get(asyncio.StreamWriter)
        ldap_session = await container.get(LDAPSession)

        while True:
            data = await self.recieve(reader)

            if not data:
                raise ConnectionAbortedError(
                    'Connection terminated by client')

            try:
                request = LDAPRequestMessage.from_bytes(data)

            except (ValidationError, IndexError, KeyError, ValueError) as err:
                log.warning(f'Invalid schema {format_exc()}')

                writer.write(LDAPRequestMessage.from_err(data, err).encode())
                await writer.drain()

            except Exception as err:
                raise RuntimeError(err) from err

            else:
                await ldap_session.queue.put(request)

    @staticmethod
    def _req_log_full(addr: str, msg: LDAPRequestMessage) -> None:
        log.debug(
            f"\nFrom: {addr!r}\n{msg.name}[{msg.message_id}]: "
            f"{msg.model_dump_json()}\n")

    @staticmethod
    def _resp_log_full(addr: str, msg: LDAPResponseMessage) -> None:
        log.debug(
            f"\nTo: {addr!r}\n{msg.name}[{msg.message_id}]: "
            f"{msg.model_dump_json()}"[:3000])

    @staticmethod
    def _log_short(addr: str, msg: LDAPMessage) -> None:
        log.info(f"\n{addr!r}: {msg.name}[{msg.message_id}]\n")

    async def _handle_single_response(self, container: AsyncContainer) -> None:
        """Get message from queue and handle it."""
        ldap_session = await container.get(LDAPSession)
        writer = await container.get(asyncio.StreamWriter)
        addr = str(await container.get(IPv4Address))

        while True:
            try:
                message = await ldap_session.queue.get()
                self.req_log(addr, message)

                async with container(scope=Scope.REQUEST) as request_container:
                    # NOTE: Automatically provides requested arguments
                    handler = await resolve_deps(
                        func=message.context.handle,
                        container=request_container)

                    async for response in message.create_response(handler):
                        self.rsp_log(addr, response)
                        writer.write(response.encode())
                        await writer.drain()

                ldap_session.queue.task_done()
            except Exception as err:
                raise RuntimeError(err) from err

    async def _handle_responses(self, container: AsyncContainer) -> None:
        """Create pool of workers and apply handler to it.

        Spawns (default 5) workers,
        then every task awaits for queue object,
        cycle locks until pool completes at least 1 task.
        """
        await asyncio.gather(
            *[self._handle_single_response(container)
                for _ in range(self.num_workers)])

    async def _get_server(self) -> asyncio.base_events.Server:
        """Get async server."""
        return await asyncio.start_server(
            self, str(self.settings.HOST), self.settings.PORT,
            flags=socket.MSG_WAITALL | socket.AI_PASSIVE,
            ssl=self.ssl_context,
        )

    @staticmethod
    async def _run_server(server: asyncio.base_events.Server) -> None:
        """Run server."""
        async with server:
            await server.serve_forever()

    @staticmethod
    def log_addrs(server: asyncio.base_events.Server) -> None:  # noqa
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        log.info(f'Server on {addrs}')

    async def start(self) -> None:
        """Run and log tcp server."""
        server = await self._get_server()

        try:
            await self._run_server(server)
        finally:
            server.close()
            await server.wait_closed()


def main() -> None:
    """Run server."""
    settings = Settings()

    async def _servers() -> None:
        nonlocal settings

        container = make_async_container(
            LDAPServerProvider(), MainProvider(), context={Settings: settings})

        settings = await container.get(Settings)
        try:
            await asyncio.gather(
                PoolClientHandler(settings, container).start(),
                PoolClientHandler(
                    settings.get_copy_4_tls(), container).start(),
            )
        finally:
            await container.close()

    with asyncio.Runner(
            loop_factory=uvloop.new_event_loop,
            debug=settings.DEBUG) as runner:
        runner.run(_servers())


if __name__ == '__main__':
    main()
