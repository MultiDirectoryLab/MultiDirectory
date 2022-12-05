"""Main MiltiDirecory module."""

import asyncio

from asyncio_pool import AioPool
from loguru import logger
from pydantic import ValidationError

from client import run_client
from ldap.messages import LDAPRequestMessage, Session


class PoolClient:
    """Async client handler.

    Don't need to wait until client sends
    request or do not need to wait until response formed.
    Can handle requests for a single client asynchronously.

    No __init__ method, as `start_server`
    uses callable object for a single connection.
    """

    def __init__(self, num_workers: int = 3):
        """Set workers number for single client concurrent handling."""
        self.num_workers = num_workers

    async def __call__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Create session, queue and start message handlers concurrently."""
        self.session = Session()
        self.queue: asyncio.Queue[LDAPRequestMessage] = asyncio.Queue()
        self.reader = reader
        self.writer = writer
        self.addr = writer.get_extra_info('peername')

        await asyncio.gather(self.handle_request(), self.handle_responses())

    async def handle_request(self):
        """Create request object and send it to queue or do nothing on err."""
        while True:
            data = await self.reader.read(4096)
            try:
                request = LDAPRequestMessage.from_bytes(data)
            except (ValidationError, IndexError, KeyError, ValueError) as err:
                logger.error(f"The connection {self.addr} raised error {err}")
            else:
                await self.queue.put(request)

    async def handle_single_response(self):
        """Get message from queue and handle it."""
        message = await self.queue.get()

        async for response in message.handle(self.session):
            logger.info(
                f"\nFrom: {self.addr!r}"
                f"\nRequest: {message}\nResponse: {response}")

            self.writer.write(response.encode())
            await self.writer.drain()

    async def handle_responses(self):
        """Create pool of workers and apply handler to it.

        Spawns (default 5) workers,
        then every task awaits for queue object,
        cycle locks until pool completes at least 1 task.
        """
        async with AioPool(self.num_workers) as pool:
            while True:
                await pool.spawn(self.handle_single_response())


async def main():
    """Start server and debug client."""
    server = await asyncio.start_server(PoolClient(), '127.0.0.1', 389)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    logger.info(f'Server on {addrs}')
    loop = asyncio.get_running_loop()
    async with server:
        task1 = loop.run_in_executor(None, run_client)
        task2 = server.serve_forever()
        await asyncio.gather(task1, task2)


if __name__ == '__main__':
    asyncio.run(main())
