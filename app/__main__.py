"""Main MiltiDirecory module."""

import asyncio

from .client import run_client
from .ldap.messages import LDAPMessage


async def handle_client(self, reader, writer):
    """Handle client connection with LDAP protocol."""
    data = await reader.read(4096)
    try:
        message = LDAPMessage.from_bytes(data)
        print(message)
    except Exception as exc:
        print('failed decoding asn1', exc)
        writer.close()
        return
    addr = writer.get_extra_info('peername')
    # print(f"Received {data}\nROS: {(message)} \nfrom {addr!r}")

    writer.write(bytearray(10))
    await writer.drain()

    print(f"Close the connection {addr}")
    writer.close()
    return


async def main():
    """Start server and debug client."""
    server = await asyncio.start_server(handle_client, '127.0.0.1', 389)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f'Connection on {addrs}')
    loop = asyncio.get_running_loop()
    async with server:
        task1 = loop.run_in_executor(None, run_client)
        task2 = server.serve_forever()
        await asyncio.gather(task1, task2)


if __name__ == '__main__':
    asyncio.run(main())
