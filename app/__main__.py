"""Main MiltiDirecory module."""

import asyncio

from loguru import logger
from pydantic import ValidationError

from client import run_client
from ldap.messages import LDAPRequestMessage, Session


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
):
    """Handle client connection with LDAP protocol."""
    session = Session()
    while True:
        data = await reader.read(4096)
        addr = writer.get_extra_info('peername')
        try:
            message = LDAPRequestMessage.from_bytes(data)
        except (ValidationError, IndexError, KeyError, ValueError) as err:
            logger.error(f"Close the connection {addr} with error {err}")
            writer.close()
            break
        else:
            async for response in message.handle(session):
                logger.info(
                    f"\nFrom: {addr!r}"
                    f"\nRequest: {message}\nResponse: {response}")

                writer.write(response.encode())
                await writer.drain()


async def main():
    """Start server and debug client."""
    server = await asyncio.start_server(handle_client, '127.0.0.1', 389)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    logger.info(f'Server on {addrs}')
    loop = asyncio.get_running_loop()
    async with server:
        task1 = loop.run_in_executor(None, run_client)
        task2 = server.serve_forever()
        await asyncio.gather(task1, task2)


if __name__ == '__main__':
    asyncio.run(main())
