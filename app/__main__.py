"""Main MiltiDirecory module."""

import asyncio
import socket
import ssl
from traceback import format_exc

from loguru import logger
from pydantic import ValidationError

from config import Settings
from ldap import LDAPRequestMessage, Session
from models.database import AsyncSession, create_session_factory

logger.add(
    "logs/file_{time:DD-MM-YYYY}.log",
    retention="10 days",
    rotation="1d",
    colorize=False)


class PoolClient:
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
        use_tls: bool = False,
    ):
        """Set workers number for single client concurrent handling."""
        self.num_workers = num_workers
        self.use_tls = use_tls
        self.settings = settings

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

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(
            self.settings.SSL_CERT, self.settings.SSL_KEY)

        if self.use_tls:
            logger.info(f"Starting TLS for {self.addr}, ciphers loaded")
            await self.writer.start_tls(ssl_context)
            logger.success(f"Successfully started TLS for {self.addr}")

        AsyncSessionFactory = create_session_factory(self.settings)  # noqa

        try:
            async with AsyncSessionFactory() as session:
                await asyncio.gather(
                    self.handle_request(),
                    self.handle_responses(session),
                )
        except RuntimeError:
            logger.error(f"The connection {self.addr} raised {format_exc()}")
        except ConnectionAbortedError:
            logger.info(
                f'Connection termination initialized by a client {self.addr}')
        finally:
            writer.close()
            await writer.wait_closed()
            logger.success(f'Connection {self.addr} normally closed')

    async def handle_request(self):
        """Create request object and send it to queue.

        :raises ConnectionAbortedError: if client sends empty request (b'')
        :raises RuntimeError: reraises on unexpected exc
        """
        while True:
            async with self.lock:
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

    async def handle_single_response(self, session: AsyncSession):
        """Get message from queue and handle it."""
        while True:
            message: LDAPRequestMessage = await self.queue.get()
            logger.info(f"\nFrom: {self.addr!r}\nRequest: {message}\n")

            async for response in message.create_response(
                    self.ldap_session, session):
                logger.info(
                    f"\nTo: {self.addr!r}\nResponse: {response}"[:3000])

                self.writer.write(response.encode())
                await self.writer.drain()

    async def handle_responses(self, session: AsyncSession):
        """Create pool of workers and apply handler to it.

        Spawns (default 5) workers,
        then every task awaits for queue object,
        cycle locks until pool completes at least 1 task.
        """
        await asyncio.gather(
            *[self.handle_single_response(session)
                for _ in range(self.num_workers)])


async def _run_server(server):
    async with server:
        await server.serve_forever()


async def main():
    """Start server and debug client."""
    settings = Settings()
    server = await asyncio.start_server(
        PoolClient(settings, use_tls=False),
        str(settings.HOST), 389,
        flags=socket.MSG_WAITALL | socket.AI_PASSIVE,
    )
    ssl_server = await asyncio.start_server(
        PoolClient(settings, use_tls=True),
        str(settings.HOST), 636,
        flags=socket.MSG_WAITALL | socket.AI_PASSIVE,
    )
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    ssl_addrs = ', '.join(
        str(sock.getsockname()) for sock in ssl_server.sockets)
    logger.info(f'Server on {addrs}, {ssl_addrs}')

    await asyncio.gather(_run_server(server), _run_server(ssl_server))


if __name__ == '__main__':
    asyncio.run(main())
