import asyncio
import socket
import sys
from ipaddress import IPv4Address, ip_address
from typing import Callable, Dict, Optional, Text, Union, cast

from ..quic.configuration import QuicConfiguration
from ..quic.connection import IFType, IPVersion, NetworkAddress, QuicConnection
from ..tls import SessionTicketHandler
from .protocol import QuicConnectionProtocol, QuicStreamHandler


class QuicClient(asyncio.DatagramProtocol):
    def __init__(
        self,
        *,
        configuration: QuicConfiguration,
        transports: Dict[str, asyncio.DatagramTransport],
        stream_handler: Optional[QuicStreamHandler] = None,
        servers: Dict[str, asyncio.DatagramProtocol],
    ) -> None:
        self.identity: Optional[NetworkAddress] = None
        self._configuration = configuration
        self._loop = asyncio.get_event_loop()
        self._protocol: Optional[QuicConnectionProtocol] = None
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._transports: Dict[str, asyncio.DatagramTransport] = transports
        self._stream_handler = stream_handler
        self._servers = servers

    def close(self):
        if self._protocol:
            self._protocol.close()
        self._transport.close()

    def set_protocol(self, protocol: QuicConnectionProtocol):
        self._protocol = protocol

    async def create_protocol(
        self,
        host: str,
        port: int,
        *,
        create_protocol: Optional[Callable] = QuicConnectionProtocol,
        session_ticket_handler: Optional[SessionTicketHandler] = None,
        wait_connected: bool = True,
    ) -> QuicConnectionProtocol:
        loop = asyncio.get_event_loop()

        # if host is not an IP address, pass it to enable SNI
        # try:
        #     ipaddress.ip_address(host)
        #     server_name = None
        # except ValueError:
        #    server_name = host

        # lookup remote address
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        addr = infos[0][4]
        if len(addr) == 2:
            # determine behaviour for IPv4
            if not sys.platform == "win32":
                # other platforms support dual-stack sockets
                addr = ("::ffff:" + addr[0], addr[1], 0, 0)
            # else:
            #   on Windows, we must use an IPv4 socket to reach an IPv4 host
            #   local_host = "0.0.0.0"

        connection = QuicConnection(
            configuration=self._configuration,
            session_ticket_handler=session_ticket_handler,
        )

        # connect
        protocol = create_protocol(connection, stream_handler=self._stream_handler)
        protocol.connection_made(self._transports)
        for server in self._servers.values():
            server = cast(QuicClient, server)
            server.set_protocol(protocol)
        protocol.connect(addr, self.identity)
        if wait_connected:
            await protocol.wait_connected()
        return protocol

    async def close_protocol(self) -> None:
        self._protocol.close()
        await self._protocol.wait_closed()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.DatagramTransport, transport)
        sock = self._transport.get_extra_info("socket")
        info = sock.getsockname()
        host = info[0]
        port = info[1]
        if type(ip_address(host)) is IPv4Address:
            host = "::ffff:" + host
        self.identity = (host, port)
        self._configuration.local_addresses.append(
            [host, IPVersion.IPV6, IFType.FIXED, port]
        )
        self._transports[host + ":" + str(port)] = self._transport
        self._servers[str(port)] = self

    def datagram_received(self, data: Union[bytes, Text], addr: NetworkAddress) -> None:
        if self._protocol is not None:
            self._protocol.datagram_received(data, addr, self.identity)


async def serve_client(
    host: str,
    port: int,
    *,
    configuration: QuicConfiguration,
    transports: Dict[str, asyncio.DatagramTransport],
    stream_handler: QuicStreamHandler = None,
    servers: Dict[str, asyncio.DatagramProtocol],
) -> QuicClient:
    """
    Start a QUIC client at the given `host` and `port`.

    :func:`serve` requires a :class:`~aioquic.quic.configuration.QuicConfiguration`
    containing TLS certificate and private key as the ``configuration`` argument.

    :func:`serve` also accepts the following optional arguments:

    * ``stream_handler`` is a callback which is invoked whenever a stream is
      created. It must accept two arguments: a :class:`asyncio.StreamReader`
      and a :class:`asyncio.StreamWriter`.
    """

    loop = asyncio.get_event_loop()

    _, protocol = await loop.create_datagram_endpoint(
        lambda: QuicClient(
            configuration=configuration,
            transports=transports,
            stream_handler=stream_handler,
            servers=servers,
        ),
        local_addr=(host, port),
    )
    protocol = cast(QuicClient, protocol)
    servers[str(protocol.identity[1])] = protocol
    return protocol
