"""Main MiltiDirecory module."""

import asyncio
import base64
import json
import math
import socket
import ssl
from contextlib import asynccontextmanager
from io import BytesIO
from ipaddress import IPv4Address
from traceback import format_exc
from typing import cast

import uvloop
from loguru import logger
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.orm import selectinload

from config import Settings
from ldap_protocol import LDAPRequestMessage, Session
from models.database import create_session_factory
from models.ldap3 import NetworkPolicy

logger.add(
    "logs/file_{time:DD-MM-YYYY}.log",
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

    def __init__(
        self,
        settings: Settings,
        num_workers: int = 3,
        rcv_size: int = 1024,
    ):
        """Set workers number for single client concurrent handling."""
        self.num_workers = num_workers
        self.settings = settings
        self.AsyncSessionFactory = create_session_factory(self.settings)
        self._size = rcv_size

        if self.settings.USE_CORE_TLS:
            with open('/certs/acme.json') as certfile:
                data = json.load(certfile)

            domain = data['md-resolver'][
                'Certificates'][0]['domain']['main']

            logger.info(f'loaded cert for {domain}')

            cert = data['md-resolver']['Certificates'][0]['certificate']
            key = data['md-resolver']['Certificates'][0]['key']

            cert = base64.b64decode(cert.encode('ascii')).decode()
            key = base64.b64decode(key.encode('ascii')).decode()

            with (
                open(self.settings.SSL_CERT, "w+") as certfile,
                open(self.settings.SSL_KEY, "w+") as keyfile,
            ):
                certfile.write(cert)
                keyfile.write(key)

            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain(
                self.settings.SSL_CERT,
                self.settings.SSL_KEY,
            )

    async def __call__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Create session, queue and start message handlers concurrently."""
        async with Session(
                reader, writer, settings=self.settings) as ldap_session:
            if (policy := await self.get_policy(ldap_session.ip)) is not None:
                ldap_session.policy = policy
            else:
                logger.warning(f"Whitelist violation from {ldap_session.addr}")
                return

            if self.settings.USE_CORE_TLS:
                await ldap_session.start_tls(self.ssl_context)

            try:
                await asyncio.gather(
                    self._handle_request(ldap_session),
                    self._handle_responses(ldap_session),
                )
            except RuntimeError:
                logger.error(
                    f"The connection {ldap_session.addr} "
                    f"raised {format_exc()}")
            except ConnectionAbortedError:
                logger.info(
                    'Connection termination initialized '
                    f'by a client {ldap_session.addr}')

    async def get_policy(self, ip: IPv4Address) -> NetworkPolicy | None:
        """Get network policies."""
        async with self.create_session() as session:
            return await session.scalar((  # noqa
                select(NetworkPolicy)
                .filter_by(enabled=True)
                .options(selectinload(NetworkPolicy.groups))
                .filter(
                    text(':ip <<= ANY("Policies".netmasks)').bindparams(ip=ip))
                .order_by(NetworkPolicy.priority.asc())
                .limit(1)
            ))

    async def recieve(self, reader: asyncio.StreamReader) -> bytes:
        """Read N packets by 1kB."""
        buffer = BytesIO()

        while True:
            packet = await reader.read(self._size)
            actual_size = buffer.write(packet)
            computed_size = self._compute_ldap_message_size(buffer.getvalue())

            if reader.at_eof() or actual_size >= computed_size:
                break

        return buffer.getvalue()

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

    async def _handle_request(self, ldap_session: Session):
        """Create request object and send it to queue.

        :raises ConnectionAbortedError: if client sends empty request (b'')
        :raises RuntimeError: reraises on unexpected exc
        """
        while True:
            data = await self.recieve(ldap_session.reader)
            # data = await ldap_session.reader.read(1500)

            if not data:
                raise ConnectionAbortedError(
                    'Connection terminated by client')

            try:
                request = LDAPRequestMessage.from_bytes(data)

            except (ValidationError, IndexError, KeyError, ValueError) as err:
                logger.warning(f'Invalid schema {format_exc()}')

                ldap_session.writer.write(
                    LDAPRequestMessage.from_err(data, err).encode())
                await ldap_session.writer.drain()

            except Exception as err:
                logger.error(f'Unexpected {format_exc()}')
                raise RuntimeError('Unexpected exception') from err

            else:
                await ldap_session.queue.put(request)

    @asynccontextmanager
    async def create_session(self):
        """Create session for request."""
        async with self.AsyncSessionFactory() as session:
            yield session

    async def _handle_single_response(self, ldap_session: Session):
        """Get message from queue and handle it."""
        while True:
            try:
                message = await ldap_session.queue.get()
                logger.info(
                    f"\nFrom: {ldap_session.addr!r}\n"
                    f"Request: {message.model_dump_json()}\n")

                async with self.create_session() as session:
                    async for response in message.create_response(
                            ldap_session, session):
                        logger.info(
                            f"\nTo: {ldap_session.addr!r}\n"
                            f"Response: {response.model_dump_json()}"[:3000])
                        ldap_session.writer.write(response.encode())
                        await ldap_session.writer.drain()
                ldap_session.queue.task_done()
            except Exception as err:
                logger.error(f'Unexpected exception {err}')
                raise err

    async def _handle_responses(self, ldap_session: Session):
        """Create pool of workers and apply handler to it.

        Spawns (default 5) workers,
        then every task awaits for queue object,
        cycle locks until pool completes at least 1 task.
        """
        await asyncio.gather(
            *[self._handle_single_response(ldap_session)
                for _ in range(self.num_workers)])

    async def _get_server(self) -> asyncio.base_events.Server:
        """Get async server."""
        return await asyncio.start_server(
            self, str(self.settings.HOST), self.settings.PORT,
            flags=socket.MSG_WAITALL | socket.AI_PASSIVE,
        )

    @staticmethod
    async def _run_server(server: asyncio.base_events.Server):
        """Run server."""
        async with server:
            await server.serve_forever()

    @staticmethod
    def log_addrs(server: asyncio.base_events.Server):  # noqa
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info(f'Server on {addrs}')

    async def start(self):
        """Run and log tcp server."""
        server = await self._get_server()
        self.log_addrs(server)
        try:
            await self._run_server(server)
        finally:
            server.close()
            await server.wait_closed()


if __name__ == '__main__':
    with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
        runner.run(PoolClientHandler(Settings()).start())
