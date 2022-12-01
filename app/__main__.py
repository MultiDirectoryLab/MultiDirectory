"""Main MiltiDirecory module."""

import asyncio

from loguru import logger

from client import run_client
from ldap.messages import LDAPRequestMessage, Session, LDAPResponseMessage
from ldap.ldap_responses import SearchResultDone, SearchResultEntry


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
            response = await message.handle(session)
        except Exception as err:
            logger.error(f"Close the connection {addr} with error {err}")
            writer.close()
            break
        else:
            logger.info(
                f"\nFrom: {addr!r}\nRequest: {message}\nResponse: {response}")

            writer.write(response.encode())
            await writer.drain()

            if isinstance(response.context, SearchResultEntry):
                writer.write(
                    LDAPResponseMessage(
                        messageID=response.message_id,
                        protocolOP=SearchResultDone.PROTOCOL_OP,
                        context=SearchResultDone(resultCode=0),
                    ).encode(),
                )
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
