"""UDP socket implementation.

usage example:
>>> import asyncio
>>> async def udp_server():
>>>     sock = await create_udp_socket(local_addr=('127.0.0.1', 9999))
>>>     while True:
>>>         packet = await sock.recvfrom()
>>>         print(packet.data, packet.addr)
>>>         sock.sendto(packet.data, packet.addr)
>>> asyncio.run(udp_server())

>>> async def udp_client():
>>>     sock = await create_udp_socket(remote_addr=('127.0.0.1', 9999))
>>>     sock.sendto(b'Hello!')
>>>     print(await sock.recvfrom())
>>>     sock.close()
>>> asyncio.run(udp_client())

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from dataclasses import dataclass

type Addr = tuple[str, int]


@dataclass(frozen=True, slots=True)
class Packet:
    """UDP incoming Packet."""

    addr: Addr
    data: bytes


class _SocketProtocol(asyncio.DatagramProtocol):
    def __init__(self, max_size: int):
        self.__error: Exception | None = None
        self.__q: asyncio.Queue[Packet | None] = asyncio.Queue(max_size)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        pass

    def connection_lost(self, _exception: Exception | None) -> None:
        self.__q.put_nowait(None)

    def datagram_received(self, data: bytes, addr: Addr) -> None:
        self.__q.put_nowait(Packet(addr, data))

    def error_received(self, exc: Exception) -> None:
        self.__error = exc
        self.__q.put_nowait(None)

    async def recvfrom(self) -> Packet | None:
        return await self.__q.get()

    def raise_on_error(self) -> None:
        if self.__error is None:
            return

        error, self.__error = self.__error, None

        raise error


class UDPSocket:
    """UDP Socket."""

    def __init__(
        self,
        transport: asyncio.DatagramTransport,
        protocol: _SocketProtocol,
    ) -> None:
        """Init transport."""
        self._transport = transport
        self._protocol = protocol

    def close(self) -> None:
        self._transport.close()

    def sendto(self, data: bytes, addr: Addr) -> None:
        self._transport.sendto(data, addr)
        self._protocol.raise_on_error()

    async def recvfrom(self) -> Packet:
        packet = await self._protocol.recvfrom()
        self._protocol.raise_on_error()

        if packet is None:
            raise ConnectionAbortedError()

        return packet

    def getsockname(self) -> Addr:
        return self._transport.get_extra_info("sockname")


async def create_udp_socket(
    local_addr: Addr | None = None,
    remote_addr: Addr | None = None,
    packets_queue_max_size: int = 0,
    reuse_port: bool = False,
) -> UDPSocket:
    """Create a UDP socket."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _SocketProtocol(packets_queue_max_size),
        local_addr=local_addr,
        remote_addr=remote_addr,
        reuse_port=reuse_port,
    )

    return UDPSocket(transport, protocol)
