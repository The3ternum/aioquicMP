import asyncio
import contextlib
import time
from unittest import TestCase

from aioquic import tls
from aioquic.quic import events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import (
    IFType,
    IPVersion,
    QuicConnection,
    QuicReceiveContext,
)
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import QuicErrorCode
from aioquic.quic.packet_builder import QuicDeliveryState
from aioquic.quic.recovery import QuicPacketPacer
from tests.utils import SERVER_CACERTFILE, SERVER_CERTFILE, SERVER_KEYFILE

CLIENT_ADDR = ("1.2.3.4", 1234)

SERVER_ADDR = ("2.3.4.5", 4433)


class SessionTicketStore:
    def __init__(self):
        self.tickets = {}

    def add(self, ticket):
        self.tickets[ticket.ticket] = ticket

    def pop(self, label):
        return self.tickets.pop(label, None)


def client_receive_context(client, epoch=tls.Epoch.ONE_RTT):
    return QuicReceiveContext(
        epoch=epoch,
        host_cid=client._receiving_uniflows[0].cid,
        network_path=client._network_paths[0],
        quic_logger_frames=[],
        time=asyncio.get_event_loop().time(),
    )


def consume_events(connection):
    while True:
        event = connection.next_event()
        if event is None:
            break


def create_standalone_client(self, **client_options):
    client = QuicConnection(
        configuration=QuicConfiguration(
            is_client=True, quic_logger=QuicLogger(), **client_options
        )
    )
    client._ack_delay = 0

    # kick-off handshake
    client.connect(SERVER_ADDR, now=time.time())
    self.assertEqual(drop(client), 1)

    return client


@contextlib.contextmanager
def client_and_server(
    client_kwargs={},
    client_options={},
    client_patch=lambda x: None,
    handshake=True,
    server_kwargs={},
    server_certfile=SERVER_CERTFILE,
    server_keyfile=SERVER_KEYFILE,
    server_options={},
    server_patch=lambda x: None,
):
    client_configuration = QuicConfiguration(
        is_client=True, quic_logger=QuicLogger(), **client_options
    )
    client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)

    client = QuicConnection(configuration=client_configuration, **client_kwargs)
    client._ack_delay = 0
    disable_packet_pacing(client)
    client_patch(client)

    server_configuration = QuicConfiguration(
        is_client=False, quic_logger=QuicLogger(), **server_options
    )
    server_configuration.load_cert_chain(server_certfile, server_keyfile)

    server = QuicConnection(configuration=server_configuration, **server_kwargs)
    server._ack_delay = 0
    disable_packet_pacing(server)
    server_patch(server)

    # perform handshake
    if handshake:
        client.connect(SERVER_ADDR, now=time.time())
        for i in range(3):
            roundtrip(client, server)

    yield client, server

    # close
    client.close()
    server.close()


def disable_packet_pacing(connection):
    class DummyPacketPacer(QuicPacketPacer):
        def next_send_time(self, now):
            return None

    connection._loss._pacer = DummyPacketPacer()


def sequence_numbers(connection_ids):
    return list(map(lambda x: x.sequence_number, connection_ids))


def address_ids(mp_network_addresses):
    return list(map(lambda x: x.address_id, mp_network_addresses))


def drop(sender):
    """
    Drop datagrams from `sender`.
    """
    return len(sender.datagrams_to_send(now=time.time()))


def roundtrip(sender, receiver):
    """
    Send datagrams from `sender` to `receiver` and back.
    """
    return transfer(sender, receiver), transfer(receiver, sender)


def transfer(sender, receiver):
    """
    Send datagrams from `sender` to `receiver`.
    """
    datagrams = 0
    from_addr = CLIENT_ADDR if sender._is_client else SERVER_ADDR
    for data, addr in sender.datagrams_to_send(now=time.time()):
        datagrams += 1
        receiver.receive_datagram(data, from_addr, now=time.time())
    return datagrams


class QuicMPConnectionTest(TestCase):
    def check_handshake(self, client, server, alpn_protocol=None):
        """
        Check handshake completed.
        """
        event = client.next_event()
        self.assertEqual(type(event), events.ProtocolNegotiated)
        self.assertEqual(event.alpn_protocol, alpn_protocol)
        event = client.next_event()
        self.assertEqual(type(event), events.HandshakeCompleted)
        self.assertEqual(event.alpn_protocol, alpn_protocol)
        self.assertEqual(event.early_data_accepted, False)
        self.assertEqual(event.session_resumed, False)
        # CID_seq 0 is implicitly communicated for initial uniflow
        for i in range(7):
            self.assertEqual(type(client.next_event()), events.ConnectionIdIssued)
        # CID_seq 0 is explicitly communicated for other uniflows
        for j in range(1, len(client._receiving_uniflows)):
            for i in range(8):
                self.assertEqual(type(client.next_event()), events.MPConnectionIdIssued)
        self.assertIsNone(client.next_event())

        event = server.next_event()
        self.assertEqual(type(event), events.ProtocolNegotiated)
        self.assertEqual(event.alpn_protocol, alpn_protocol)
        event = server.next_event()
        self.assertEqual(type(event), events.HandshakeCompleted)
        self.assertEqual(event.alpn_protocol, alpn_protocol)
        # CID_seq 0 is implicitly communicated for initial uniflow
        for i in range(7):
            self.assertEqual(type(server.next_event()), events.ConnectionIdIssued)
        # CID_seq 0 is explicitly communicated for other uniflows
        for j in range(1, len(server._receiving_uniflows)):
            for i in range(8):
                self.assertEqual(type(server.next_event()), events.MPConnectionIdIssued)
        self.assertIsNone(server.next_event())

    def test_mp_connect(self):
        client_msui = 1
        server_msui = 1
        assert client_msui >= 0 and server_msui >= 0
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            # check handshake completed
            self.check_handshake(client=client, server=server)

            # check each endpoint has available connection IDs for each uniflow for the peer
            for i in range(client_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._sending_uniflows[i].cid_available),
                    [1, 2, 3, 4, 5, 6, 7],
                )
            for i in range(server_msui + 1):
                self.assertEqual(
                    sequence_numbers(server._sending_uniflows[i].cid_available),
                    [1, 2, 3, 4, 5, 6, 7],
                )

            # client closes the connection
            client.close()
            self.assertEqual(transfer(client, server), 1)

            # check connection closes on the client side
            client.handle_timer(client.get_timer())
            event = client.next_event()
            self.assertEqual(type(event), events.ConnectionTerminated)
            self.assertEqual(event.error_code, QuicErrorCode.NO_ERROR)
            self.assertEqual(event.frame_type, None)
            self.assertEqual(event.reason_phrase, "")
            self.assertIsNone(client.next_event())

            # check connection closes on the server side
            server.handle_timer(server.get_timer())
            event = server.next_event()
            self.assertEqual(type(event), events.ConnectionTerminated)
            self.assertEqual(event.error_code, QuicErrorCode.NO_ERROR)
            self.assertEqual(event.frame_type, None)
            self.assertEqual(event.reason_phrase, "")
            self.assertIsNone(server.next_event())

            # check client log
            client_log = client.configuration.quic_logger.to_dict()
            self.assertGreater(len(client_log["traces"][0]["events"]), 20)

            # check server log
            server_log = server.configuration.quic_logger.to_dict()
            self.assertGreater(len(server_log["traces"][0]["events"]), 20)

    def test_mp_change_connection_id(self):
        client_msui = 1
        server_msui = 0
        client_uniflow_id = 1
        assert client_msui >= client_uniflow_id >= 0
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            for i in range(client_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._sending_uniflows[i].cid_available),
                    [1, 2, 3, 4, 5, 6, 7],
                )

            # the client changes connection ID
            client.change_connection_id(client_uniflow_id)
            self.assertEqual(transfer(client, server), 1)
            for i in range(client_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._sending_uniflows[i].cid_available),
                    (
                        [2, 3, 4, 5, 6, 7]
                        if i == client_uniflow_id
                        else [1, 2, 3, 4, 5, 6, 7]
                    ),
                )

            # the server provides a new connection ID
            self.assertEqual(transfer(server, client), 1)
            for i in range(client_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._sending_uniflows[i].cid_available),
                    (
                        [2, 3, 4, 5, 6, 7, 8]
                        if i == client_uniflow_id
                        else [1, 2, 3, 4, 5, 6, 7]
                    ),
                )

    def test_mp_change_connection_id_retransmit_new_connection_id(self):
        client_msui = 1
        server_msui = 0
        client_uniflow_id = 1
        assert client_msui >= client_uniflow_id >= 1
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            for i in range(client_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._sending_uniflows[i].cid_available),
                    [1, 2, 3, 4, 5, 6, 7],
                )

            # the client changes connection ID
            client.change_connection_id(client_uniflow_id)
            self.assertEqual(transfer(client, server), 1)
            for i in range(client_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._sending_uniflows[i].cid_available),
                    (
                        [2, 3, 4, 5, 6, 7]
                        if i == client_uniflow_id
                        else [1, 2, 3, 4, 5, 6, 7]
                    ),
                )

            # the server provides a new connection ID, MP_NEW_CONNECTION_ID is lost
            self.assertEqual(drop(server), 1)
            for i in range(client_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._sending_uniflows[i].cid_available),
                    (
                        [2, 3, 4, 5, 6, 7]
                        if i == client_uniflow_id
                        else [1, 2, 3, 4, 5, 6, 7]
                    ),
                )

            # MP_NEW_CONNECTION_ID is retransmitted
            server._on_mp_new_connection_id_delivery(
                QuicDeliveryState.LOST,
                server._receiving_uniflows[client_uniflow_id].cid_available[-1],
                client_uniflow_id,
            )
            self.assertEqual(transfer(server, client), 1)
            for i in range(client_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._sending_uniflows[i].cid_available),
                    (
                        [2, 3, 4, 5, 6, 7, 8]
                        if i == client_uniflow_id
                        else [1, 2, 3, 4, 5, 6, 7]
                    ),
                )

    def test_mp_change_connection_id_retransmit_retire_connection_id(self):
        client_msui = 1
        server_msui = 0
        client_uniflow_id = 1
        assert client_msui >= client_uniflow_id >= 1
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            for i in range(client_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._sending_uniflows[i].cid_available),
                    [1, 2, 3, 4, 5, 6, 7],
                )

            # the client changes connection ID, MP_RETIRE_CONNECTION_ID is lost
            client.change_connection_id(client_uniflow_id)
            self.assertEqual(drop(client), 1)
            for i in range(client_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._sending_uniflows[i].cid_available),
                    (
                        [2, 3, 4, 5, 6, 7]
                        if i == client_uniflow_id
                        else [1, 2, 3, 4, 5, 6, 7]
                    ),
                )

            # MP_RETIRE_CONNECTION_ID is retransmitted
            client._on_mp_retire_connection_id_delivery(
                QuicDeliveryState.LOST, 0, client_uniflow_id
            )
            self.assertEqual(transfer(client, server), 1)

            # the server provides a new connection ID
            self.assertEqual(transfer(server, client), 1)
            for i in range(client_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._sending_uniflows[i].cid_available),
                    (
                        [2, 3, 4, 5, 6, 7, 8]
                        if i == client_uniflow_id
                        else [1, 2, 3, 4, 5, 6, 7]
                    ),
                )

    def test_mp_remove_address(self):
        address_id = 1
        with client_and_server(
            server_options={
                "local_addresses": [
                    ["::1", IPVersion.IPV6, IFType.FIXED, 4433],
                    ["::1", IPVersion.IPV6, IFType.FIXED, 4444],
                    ["::1", IPVersion.IPV6, IFType.FIXED, 4455],
                ]
            },
        ) as (client, server):
            self.assertEqual(address_ids(client._remote_addresses.values()), [0, 1, 2])

            # the server removes the second address, REMOVE_ADDRESS is sent
            server.remove_address(address_id)
            self.assertEqual(transfer(server, client), 1)
            self.assertEqual(client._remote_addresses[address_id].is_removed, True)
