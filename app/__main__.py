"""Main MiltiDirecory module."""

import asyncio
import socket
import ssl
from contextlib import asynccontextmanager
from traceback import format_exc

from loguru import logger
from pydantic import ValidationError

from config import Settings
from ldap_protocol import LDAPRequestMessage, Session
from models.database import create_session_factory

logger.add(
    "logs/file_{time:DD-MM-YYYY}.log",
    retention="10 days",
    rotation="1d",
    colorize=False)


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
    ):
        """Set workers number for single client concurrent handling."""
        self.num_workers = num_workers
        self.settings = settings
        self.AsyncSessionFactory = create_session_factory(self.settings)

    async def __call__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Create session, queue and start message handlers concurrently."""
        self.ldap_session = Session()
        self.queue: asyncio.Queue[LDAPRequestMessage] = asyncio.Queue()
        self.reader = reader
        self.writer = writer
        self.lock = asyncio.Lock()
        self.addr = ':'.join(map(str, writer.get_extra_info('peername')))

        if self.settings.USE_CORE_TLS:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(
                self.settings.SSL_CERT, self.settings.SSL_KEY)
            logger.info(f"Starting TLS for {self.addr}, ciphers loaded")
            await self.writer.start_tls(ssl_context)
            logger.success(f"Successfully started TLS for {self.addr}")

        handle = asyncio.create_task(self.handle_responses())

        try:
            await asyncio.gather(self.handle_request(), handle)
        except RuntimeError:
            logger.error(f"The connection {self.addr} raised {format_exc()}")
        except ConnectionAbortedError:
            logger.info(
                f'Connection termination initialized by a client {self.addr}')
        finally:
            writer.close()
            await writer.wait_closed()
            await handle
            logger.success(f'Connection {self.addr} normally closed')

    async def handle_request(self):
        """Create request object and send it to queue.

        :raises ConnectionAbortedError: if client sends empty request (b'')
        :raises RuntimeError: reraises on unexpected exc
        """
        while True:
            data = await self.reader.read(4096)

            if not data:
                raise ConnectionAbortedError(
                    'Connection terminated by client')

            try:
                request = LDAPRequestMessage.from_bytes(data)

            except (
                ValidationError, IndexError,
                KeyError, ValueError,
            ) as err:
                logger.warning(f'Invalid schema {format_exc()}')

                self.writer.write(
                    LDAPRequestMessage.from_err(data, err).encode())
                await self.writer.drain()

            except Exception as err:
                logger.error(f'Unexpected {format_exc()}')
                raise RuntimeError('Unexpected exception') from err

            else:
                await self.queue.put(request)

    @asynccontextmanager
    async def create_session(self):
        """Create session for request."""
        async with self.AsyncSessionFactory() as session:
            yield session

    async def handle_single_response(self):
        """Get message from queue and handle it."""
        while True:
            message = await self.queue.get()
            logger.info(f"\nFrom: {self.addr!r}\nRequest: {message}\n")

            async with self.create_session() as session:
                async for response in message.create_response(
                        self.ldap_session, session):
                    logger.info(
                        f"\nTo: {self.addr!r}\nResponse: {response}"[:3000])

                    self.writer.write(response.encode())
                    await self.writer.drain()

    async def handle_responses(self):
        """Create pool of workers and apply handler to it.

        Spawns (default 5) workers,
        then every task awaits for queue object,
        cycle locks until pool completes at least 1 task.
        """
        await asyncio.gather(
            *[self.handle_single_response() for _ in range(self.num_workers)])

    async def get_server(self) -> asyncio.base_events.Server:
        """Get async server."""
        return await asyncio.start_server(
            self, str(self.settings.HOST), self.settings.PORT,
            flags=socket.MSG_WAITALL | socket.AI_PASSIVE,
        )

    @staticmethod
    async def run_server(server: asyncio.base_events.Server):
        """Run server."""
        async with server:
            try:
                await server.serve_forever()
            finally:
                server.close()

    @staticmethod
    def log_addrs(server: asyncio.base_events.Server):  # noqa
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info(f'Server on {addrs}')

    async def start(self):
        """Run and log tcp server."""
        server = await self.get_server()
        self.log_addrs(server)
        await self.run_server(server)


if __name__ == '__main__':
    asyncio.run(PoolClientHandler(Settings()).start())
