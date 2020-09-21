import argparse
import asyncio
import logging
import pickle
import ssl
from typing import List, Optional, cast

from dnslib.dns import QTYPE, DNSQuestion, DNSRecord

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from examples.quic_logger import QuicDirectoryLogger

logger = logging.getLogger("client")


class DoQClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_waiter: Optional[asyncio.Future[None]] = None

    async def query(self, query_type: str, dns_query: str) -> None:
        query = DNSRecord(q=DNSQuestion(dns_query, getattr(QTYPE, query_type)))
        stream_id = self._quic.get_next_available_stream_id()
        logger.debug(f"Stream ID: {stream_id}")
        end_stream = False
        self._quic.send_stream_data(stream_id, bytes(query.pack()), end_stream)
        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._ack_waiter is not None:
            if isinstance(event, StreamDataReceived):
                answer = DNSRecord.parse(event.data)
                logger.info(answer)
                waiter = self._ack_waiter
                self._ack_waiter = None
                waiter.set_result(None)


def save_session_ticket(ticket):
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


async def run(
    local_host: str,
    local_ports: List[int],
    local_preferred_port: int,
    configuration: QuicConfiguration,
    host: str,
    port: int,
    query_type: str,
    dns_query: str,
) -> None:
    logger.debug(f"Connecting to {host}:{port}")
    async with connect(
        local_host,
        local_ports,
        local_preferred_port,
        host,
        port,
        configuration=configuration,
        create_protocol=DoQClient,
        session_ticket_handler=save_session_ticket,
    ) as client:
        client = cast(DoQClient, client)

        logger.debug("Sending DNS query")
        await client.query(query_type, dns_query)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS over QUIC client")
    parser.add_argument("-t", "--type", type=str, help="Type of record to ")
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        help="The remote peer's host name or IP address",
    )
    parser.add_argument(
        "--port", type=int, default=784, help="The remote peer's port number"
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )
    parser.add_argument("--dns_type", help="The DNS query type to send")
    parser.add_argument("--query", help="Domain to query")
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
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
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
        alpn_protocols=["dq"],
        is_client=True,
        max_datagram_frame_size=65536,
        max_sending_uniflow_id=max_sending_uniflows_id,
    )
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.quic_log:
        configuration.quic_logger = QuicDirectoryLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            logger.debug(f"Unable to read {args.session_ticket}")
            pass
    else:
        logger.debug("No session ticket defined...")

    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        run(
            local_host=args.local_host,
            local_ports=local_ports,
            local_preferred_port=args.local_preferred_port,
            configuration=configuration,
            host=args.host,
            port=args.port,
            query_type=args.dns_type,
            dns_query=args.query,
        )
    )
