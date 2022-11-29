"""Main MiltiDirecory module."""

import asyncio

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
            response = await message.handle(session)
        except Exception as err:
            print(err)
            print(f"Close the connection {addr}")
            writer.close()
        else:
            print(f"From: {addr!r}\nRequest: {message}\nResponse: {response}")

            writer.write(response.encode())
            await writer.drain()


async def main():
    """Start server and debug client."""
    server = await asyncio.start_server(handle_client, '127.0.0.1', 389)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f'Server on {addrs}')
    loop = asyncio.get_running_loop()
    async with server:
        task1 = loop.run_in_executor(None, run_client)
        task2 = server.serve_forever()
        await asyncio.gather(task1, task2)


if __name__ == '__main__':
    asyncio.run(main())
