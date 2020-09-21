import asyncio
import socket
import sys
from ipaddress import IPv4Address, ip_address
from typing import AsyncGenerator, Callable, Dict, List, Optional, Text, Union, cast

from ..quic.configuration import QuicConfiguration
from ..quic.connection import IFType, IPVersion, NetworkAddress, QuicConnection
from ..tls import SessionTicketHandler
from .compat import asynccontextmanager
from .protocol import QuicConnectionProtocol, QuicStreamHandler

__all__ = ["connect"]


class QuicClient(asyncio.DatagramProtocol):
    def __init__(
        self,
        *,
        configuration: QuicConfiguration,
        transports: Dict[str, asyncio.DatagramTransport],
        servers: Dict,  # Dict[str, QuicClient]
    ) -> None:
        self.identity: Optional[NetworkAddress] = None
        self._configuration = configuration
        self._protocol: Optional[QuicConnectionProtocol] = None
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._transports: Dict[str, asyncio.DatagramTransport] = transports
        self._servers = servers

    async def close(self, close_protocol: bool):
        if close_protocol and self._protocol is not None:
            self._protocol.close()
            await self._protocol.wait_closed()
            self._protocol = None
        self._transports.pop(self.identity[0] + ":" + str(self.identity[1]))
        self._transport.close()

    def set_protocol(self, protocol: QuicConnectionProtocol):
        self._protocol = protocol

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.DatagramTransport, transport)
        sock = self._transport.get_extra_info("socket")
        info = sock.getsockname()
        host = info[0]
        port = info[1]
        if type(ip_address(host)) is IPv4Address:
            host = "::ffff:" + host
        elif host == "::":
            host = "::ffff:127.0.0.1"
        self.identity = (host, port)
        self._configuration.local_addresses.append(
            [host, IPVersion.IPV6, IFType.FIXED, port]
        )
        self._transports[host + ":" + str(port)] = self._transport
        self._servers[str(port)] = self

    def datagram_received(self, data: Union[bytes, Text], addr: NetworkAddress) -> None:
        if self._protocol is not None:
            self._protocol.datagram_received(data, addr, self.identity)


@asynccontextmanager
async def connect(
    local_host: str,
    local_ports: List[int],
    local_preferred_port: int,
    host: str,
    port: int,
    *,
    configuration: Optional[QuicConfiguration] = None,
    create_protocol: Optional[Callable] = QuicConnectionProtocol,
    session_ticket_handler: Optional[SessionTicketHandler] = None,
    stream_handler: Optional[QuicStreamHandler] = None,
    wait_connected: bool = True,
) -> AsyncGenerator[QuicConnectionProtocol, None]:
    """
    Start a QUIC client at the given 'local_host and local_ports'.
    Connect to a QUIC server at the given `host` and `port`
    from a selected local_preferred_port.

    :meth:`connect()` returns an awaitable. Awaiting it yields a
    :class:`~aioquic.asyncio.QuicConnectionProtocol` which can be used to
    create streams.

    :func:`connect` also accepts the following optional arguments:

    * ``configuration`` is a :class:`~aioquic.quic.configuration.QuicConfiguration`
      configuration object.
    * ``create_protocol`` allows customizing the :class:`~asyncio.Protocol` that
      manages the connection. It should be a callable or class accepting the same
      arguments as :class:`~aioquic.asyncio.QuicConnectionProtocol` and returning
      an instance of :class:`~aioquic.asyncio.QuicConnectionProtocol` or a subclass.
    * ``session_ticket_handler`` is a callback which is invoked by the TLS
      engine when a new session ticket is received.
    * ``stream_handler`` is a callback which is invoked whenever a stream is
      created. It must accept two arguments: a :class:`asyncio.StreamReader`
      and a :class:`asyncio.StreamWriter`.
    """
    loop = asyncio.get_event_loop()

    # if host is not an IP address, pass it to enable SNI
    try:
        ip_address(host)
        server_name = None
    except ValueError:
        server_name = host

    # lookup remote address
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    addr = infos[0][4]
    if len(addr) == 2:
        # determine behaviour for IPv4
        if sys.platform == "win32":
            # on Windows, we must use an IPv4 socket to reach an IPv4 host
            local_host = "0.0.0.0"
        else:
            # other platforms support dual-stack sockets
            addr = ("::ffff:" + addr[0], addr[1], 0, 0)

    if configuration is None:
        configuration = QuicConfiguration(is_client=True)
    if server_name is not None:
        configuration.server_name = server_name

    # create the client endpoint
    servers: Dict[str, QuicClient] = {}
    transports: Dict[str, asyncio.DatagramTransport] = {}
    for local_port in local_ports:
        await loop.create_datagram_endpoint(
            lambda: QuicClient(
                configuration=configuration,
                transports=transports,
                servers=servers,
            ),
            local_addr=(local_host, local_port),
        )

    # prepare QUIC connection
    connection = QuicConnection(
        configuration=configuration, session_ticket_handler=session_ticket_handler
    )
    protocol = create_protocol(connection, stream_handler=stream_handler)
    protocol.connection_made(transports)
    for server in servers.values():
        server.set_protocol(protocol)

    # connect
    if len(local_ports) == 1 and local_ports[0] == 0 and local_preferred_port == 0:
        local_addr = list(servers.values())[0].identity
    else:
        local_addr = servers[str(local_preferred_port)].identity
    protocol.connect(addr, local_addr)
    if wait_connected:
        await protocol.wait_connected()
    try:
        yield protocol
    finally:
        protocol.close()
    await protocol.wait_closed()
    for server in servers.values():
        await server.close(False)
