import argparse
import asyncio
import logging
import ssl
from typing import Dict, Optional, cast

from aioquic.asyncio.client import QuicClient, serve_client
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import DatagramFrameReceived, QuicEvent
from examples.quic_logger import QuicDirectoryLogger

logger = logging.getLogger("client")


class SiduckClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_waiter: Optional[asyncio.Future[None]] = None

    async def quack(self) -> None:
        assert self._ack_waiter is None, "Only one quack at a time."
        self._quic.send_datagram_frame(b"quack")

        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._ack_waiter is not None:
            if isinstance(event, DatagramFrameReceived) and event.data == b"quack-ack":
                waiter = self._ack_waiter
                self._ack_waiter = None
                waiter.set_result(None)


async def run(host: str, port: int, server: QuicClient) -> None:
    protocol = await server.create_protocol(
        host,
        port,
        create_protocol=SiduckClient,
    )
    protocol = cast(SiduckClient, protocol)

    logger.info("sending quack")
    await protocol.quack()
    logger.info("received quack-ack")

    await server.close_protocol()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SiDUCK client")
    parser.add_argument(
        "host", type=str, help="The remote peer's host name or IP address"
    )
    parser.add_argument("port", type=int, help="The remote peer's port number")
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )
    parser.add_argument(
        "--local-host",
        type=str,
        default="::",
        help="listen on the specified address (defaults to ::)",
    )
    parser.add_argument(
        "--local-ports",
        type=str,
        default="5533 5544 5555",
        help="listen on the specified port (defaults to 5533, 5544, 5555)",
    )
    parser.add_argument(
        "--local-preferred-port",
        type=str,
        default="5533",
        help="Send the request from the specified port",
    )
    parser.add_argument(
        "-m",
        "--multipath",
        type=int,
        default=0,
        help="Set the maximum number of sending uniflows",
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    # collect the ports
    local_ports = args.local_ports.split(" ")
    local_ports = [int(p) for p in local_ports]

    # get max number of sending uniflows
    max_sending_uniflows_id = args.multipath

    configuration = QuicConfiguration(
        alpn_protocols=["siduck"],
        is_client=True,
        max_datagram_frame_size=65536,
        max_sending_uniflow_id=max_sending_uniflows_id,
    )
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.quic_log:
        configuration.quic_logger = QuicDirectoryLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")

    servers: Dict[str, QuicClient] = {}
    transports: Dict[str, asyncio.DatagramTransport] = {}

    loop = asyncio.get_event_loop()
    for local_port in local_ports:
        loop.run_until_complete(
            serve_client(
                args.local_host,
                local_port,
                configuration=configuration,
                transports=transports,
                servers=servers,
            )
        )
    loop.run_until_complete(
        run(
            host=args.host,
            port=args.port,
            server=servers[str(args.local_preferred_port)],
        )
    )
