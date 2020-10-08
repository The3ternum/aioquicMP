import asyncio
import contextlib
import time
from unittest import TestCase

from aioquic import tls
from aioquic.buffer import Buffer
from aioquic.quic import events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import (
    IFType,
    IPVersion,
    QuicConnection,
    QuicConnectionError,
    QuicReceiveContext,
)
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import QuicErrorCode, QuicFrameType
from aioquic.quic.packet_builder import QuicDeliveryState
from aioquic.quic.recovery import QuicPacketPacer
from tests.utils import SERVER_CACERTFILE, SERVER_CERTFILE, SERVER_KEYFILE

CLIENT_ADDR = ("1.2.3.4", 1234)

SERVER_ADDR = ("2.3.4.5", 4433)


def client_receive_context(client, receiving_uniflow: int = 0, epoch=tls.Epoch.ONE_RTT):
    return QuicReceiveContext(
        epoch=epoch,
        host_cid=client._receiving_uniflows[receiving_uniflow].cid,
        receiving_uniflow=client._receiving_uniflows[receiving_uniflow],
        perceived_address=client._receiving_uniflows[receiving_uniflow].source_address,
        # perceived_address=client._perceived_remote_addresses[0],
        quic_logger_frames=[],
        time=asyncio.get_event_loop().time(),
    )


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
        is_client=True,
        quic_logger=QuicLogger(),
        local_addresses=[
            [CLIENT_ADDR[0], IPVersion.IPV4, IFType.FIXED, CLIENT_ADDR[1]]
        ],
        **client_options,
    )
    client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)

    client = QuicConnection(configuration=client_configuration, **client_kwargs)
    client._ack_delay = 0
    disable_packet_pacing(client)
    client_patch(client)

    server_configuration = QuicConfiguration(
        is_client=False,
        quic_logger=QuicLogger(),
        local_addresses=[
            [SERVER_ADDR[0], IPVersion.IPV4, IFType.FIXED, SERVER_ADDR[1]]
        ],
        **server_options,
    )
    server_configuration.load_cert_chain(server_certfile, server_keyfile)

    server = QuicConnection(
        configuration=server_configuration,
        original_destination_connection_id=client.original_destination_connection_id,
        **server_kwargs,
    )
    server._ack_delay = 0
    disable_packet_pacing(server)
    server_patch(server)

    # perform handshake
    if handshake:
        client.connect(SERVER_ADDR, CLIENT_ADDR, now=time.time())
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

    for suniflow in connection._sending_uniflows.values():
        suniflow.loss._pacer = DummyPacketPacer()


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
    to_addr = SERVER_ADDR if sender._is_client else CLIENT_ADDR
    for data, addr, local_addr in sender.datagrams_to_send(now=time.time()):
        datagrams += 1
        receiver.receive_datagram(data, from_addr, to_addr, now=time.time())
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

    def test_mp_unsupported_client(self):
        test_frames = [
            {
                "function": 0,
                "frame_type": QuicFrameType.MP_NEW_CONNECTION_ID,
                "buffer": Buffer(data=b""),
            },
            {
                "function": 1,
                "frame_type": QuicFrameType.MP_RETIRE_CONNECTION_ID,
                "buffer": Buffer(data=b""),
            },
            {
                "function": 2,
                "frame_type": QuicFrameType.MP_ACK_ECN,
                "buffer": Buffer(data=b""),
            },
            {
                "function": 3,
                "frame_type": QuicFrameType.ADD_ADDRESS,
                "buffer": Buffer(data=b""),
            },
            {
                "function": 4,
                "frame_type": QuicFrameType.REMOVE_ADDRESS,
                "buffer": Buffer(data=b""),
            },
            {
                "function": 5,
                "frame_type": QuicFrameType.UNIFLOWS,
                "buffer": Buffer(data=b""),
            },
        ]
        for item in test_frames:
            with client_and_server(
                server_options={"max_sending_uniflow_id": None},
            ) as (client, server):
                function_objects = [
                    client._handle_mp_new_connection_id_frame,
                    client._handle_mp_retire_connection_id_frame,
                    client._handle_mp_ack_frame,
                    client._handle_add_address_frame,
                    client._handle_remove_address_frame,
                    client._handle_uniflows_frame,
                ]
                with self.assertRaises(QuicConnectionError) as cm:
                    # client receives a multipath frame
                    function_objects[item["function"]](
                        client_receive_context(client),
                        int(item["frame_type"]),
                        item["buffer"],
                    )
                self.assertEqual(
                    cm.exception.error_code,
                    QuicErrorCode.PROTOCOL_VIOLATION,
                )
                self.assertEqual(cm.exception.frame_type, item["frame_type"])
                self.assertEqual(
                    cm.exception.reason_phrase,
                    "Multipath frames are not allowed, use max_sending_uniflow_id to signal Multipath support",
                )

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

    def test_mp_handle_new_connection_id_duplicate(self):
        client_msui = 1
        server_msui = 0
        client_uniflow_id = 1
        assert client_msui >= client_uniflow_id >= 1
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            buf = Buffer(capacity=100)
            buf.push_uint_var(client_uniflow_id)  # uniflow_id
            buf.push_uint_var(7)  # sequence_number
            buf.push_uint_var(0)  # retire_prior_to
            buf.push_uint8(8)
            buf.push_bytes(bytes(8))
            buf.push_bytes(bytes(16))
            buf.seek(0)

            # client receives NEW_CONNECTION_ID
            client._handle_mp_new_connection_id_frame(
                client_receive_context(client),
                QuicFrameType.NEW_CONNECTION_ID,
                buf,
            )

            for i in range(client_msui + 1):
                self.assertEqual(client._sending_uniflows[i].cid.sequence_number, 0)
                self.assertEqual(
                    sequence_numbers(client._sending_uniflows[i].cid_available),
                    [1, 2, 3, 4, 5, 6, 7],
                )

    def test_mp_handle_new_connection_id_over_limit(self):
        client_msui = 1
        server_msui = 0
        client_uniflow_id = 1
        assert client_msui >= client_uniflow_id >= 1
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            buf = Buffer(capacity=100)
            buf.push_uint_var(client_uniflow_id)  # uniflow_id
            buf.push_uint_var(8)  # sequence_number
            buf.push_uint_var(0)  # retire_prior_to
            buf.push_uint8(8)
            buf.push_bytes(bytes(8))
            buf.push_bytes(bytes(16))
            buf.seek(0)

            # client receives MP_NEW_CONNECTION_ID
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_mp_new_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.MP_NEW_CONNECTION_ID,
                    buf,
                )
            self.assertEqual(
                cm.exception.error_code, QuicErrorCode.CONNECTION_ID_LIMIT_ERROR
            )
            self.assertEqual(
                cm.exception.frame_type, QuicFrameType.MP_NEW_CONNECTION_ID
            )
            self.assertEqual(
                cm.exception.reason_phrase,
                "Uniflow " + str(client_uniflow_id) + " too many active connection IDs",
            )

    def test_mp_handle_new_connection_id_with_retire_prior_to(self):
        client_msui = 1
        server_msui = 0
        client_uniflow_id = 1
        assert client_msui >= client_uniflow_id >= 1
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            buf = Buffer(capacity=100)
            buf.push_uint_var(client_uniflow_id)  # uniflow_id
            buf.push_uint_var(8)  # sequence_number
            buf.push_uint_var(2)  # retire_prior_to
            buf.push_uint8(8)
            buf.push_bytes(bytes(8))
            buf.push_bytes(bytes(16))
            buf.seek(0)

            # client receives MP_NEW_CONNECTION_ID
            client._handle_mp_new_connection_id_frame(
                client_receive_context(client),
                QuicFrameType.MP_NEW_CONNECTION_ID,
                buf,
            )

            for i in range(client_msui + 1):
                self.assertEqual(
                    client._sending_uniflows[i].cid.sequence_number,
                    2 if i == client_uniflow_id else 0,
                )
            self.assertEqual(
                sequence_numbers(
                    client._sending_uniflows[client_uniflow_id].cid_available
                ),
                [3, 4, 5, 6, 7, 8] if i == client_uniflow_id else [1, 2, 3, 4, 5, 6, 7],
            )

    def test_mp_handle_new_connection_id_with_retire_prior_to_invalid(self):
        client_msui = 1
        server_msui = 0
        client_uniflow_id = 1
        assert client_msui >= client_uniflow_id >= 1
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            buf = Buffer(capacity=100)
            buf.push_uint_var(client_uniflow_id)  # uniflow_id
            buf.push_uint_var(8)  # sequence_number
            buf.push_uint_var(9)  # retire_prior_to
            buf.push_uint8(8)
            buf.push_bytes(bytes(8))
            buf.push_bytes(bytes(16))
            buf.seek(0)

            # client receives MP_NEW_CONNECTION_ID
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_mp_new_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.MP_NEW_CONNECTION_ID,
                    buf,
                )
            self.assertEqual(
                cm.exception.error_code,
                QuicErrorCode.PROTOCOL_VIOLATION,
            )
            self.assertEqual(
                cm.exception.frame_type, QuicFrameType.MP_NEW_CONNECTION_ID
            )
            self.assertEqual(
                cm.exception.reason_phrase,
                "Uniflow "
                + str(client_uniflow_id)
                + " retire_prior_to is greater than the sequence_number",
            )

    def test_mp_handle_retire_connection_id_frame(self):
        client_msui = 0
        server_msui = 1
        server_uniflow_id = 1
        assert server_msui >= server_uniflow_id >= 1
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            for i in range(server_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._receiving_uniflows[i].cid_available),
                    [0, 1, 2, 3, 4, 5, 6, 7],
                )

            buf = Buffer(capacity=100)
            buf.push_uint_var(server_uniflow_id)  # uniflow_id
            buf.push_uint_var(2)  # sequence_number
            buf.seek(0)

            # client receives MP_RETIRE_CONNECTION_ID
            client._handle_mp_retire_connection_id_frame(
                client_receive_context(client),
                QuicFrameType.MP_RETIRE_CONNECTION_ID,
                buf,
            )

            for i in range(server_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._receiving_uniflows[i].cid_available),
                    [0, 1, 3, 4, 5, 6, 7, 8]
                    if i == server_uniflow_id
                    else [0, 1, 2, 3, 4, 5, 6, 7],
                )

    def test_mp_handle_retire_connection_id_frame_current_cid(self):
        client_msui = 0
        server_msui = 1
        server_uniflow_id = 1
        assert server_msui >= server_uniflow_id >= 1
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            for i in range(server_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._receiving_uniflows[i].cid_available),
                    [0, 1, 2, 3, 4, 5, 6, 7],
                )

            buf = Buffer(capacity=100)
            buf.push_uint_var(server_uniflow_id)  # uniflow_id
            buf.push_uint_var(0)  # sequence_number
            buf.seek(0)

            # client receives MP_RETIRE_CONNECTION_ID for the current CID
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_mp_retire_connection_id_frame(
                    client_receive_context(client, receiving_uniflow=server_uniflow_id),
                    QuicFrameType.MP_RETIRE_CONNECTION_ID,
                    buf,
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
            self.assertEqual(
                cm.exception.frame_type, QuicFrameType.MP_RETIRE_CONNECTION_ID
            )
            self.assertEqual(
                cm.exception.reason_phrase,
                "Uniflow "
                + str(server_uniflow_id)
                + " cannot retire current connection ID",
            )
            for i in range(server_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._receiving_uniflows[i].cid_available),
                    [0, 1, 2, 3, 4, 5, 6, 7],
                )

    def test_handle_retire_connection_id_frame_invalid_sequence_number(self):
        client_msui = 0
        server_msui = 1
        server_uniflow_id = 1
        assert server_msui >= server_uniflow_id >= 1
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            for i in range(server_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._receiving_uniflows[i].cid_available),
                    [0, 1, 2, 3, 4, 5, 6, 7],
                )

            buf = Buffer(capacity=100)
            buf.push_uint_var(server_uniflow_id)  # uniflow_id
            buf.push_uint_var(8)  # sequence_number
            buf.seek(0)

            # client receives MP_RETIRE_CONNECTION_ID
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_mp_retire_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.MP_RETIRE_CONNECTION_ID,
                    buf,
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
            self.assertEqual(
                cm.exception.frame_type, QuicFrameType.MP_RETIRE_CONNECTION_ID
            )
            self.assertEqual(
                cm.exception.reason_phrase,
                "Uniflow "
                + str(server_uniflow_id)
                + " cannot retire unknown connection ID",
            )
            for i in range(server_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._receiving_uniflows[i].cid_available),
                    [0, 1, 2, 3, 4, 5, 6, 7],
                )

    def test_mp_handle_new_connection_id_invalid_uniflow_id(self):
        client_msui = 1
        server_msui = 0
        client_uniflow_id = 2
        assert client_uniflow_id > client_msui >= 1
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            buf = Buffer(capacity=100)
            buf.push_uint_var(client_uniflow_id)  # uniflow_id
            buf.push_uint_var(8)  # sequence_number
            buf.push_uint_var(0)  # retire_prior_to
            buf.push_uint8(8)
            buf.push_bytes(bytes(8))
            buf.push_bytes(bytes(16))
            buf.seek(0)

            # client receives MP_NEW_CONNECTION_ID
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_mp_new_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.MP_NEW_CONNECTION_ID,
                    buf,
                )
            self.assertEqual(
                cm.exception.error_code,
                QuicErrorCode.PROTOCOL_VIOLATION,
            )
            self.assertEqual(
                cm.exception.frame_type, QuicFrameType.MP_NEW_CONNECTION_ID
            )
            self.assertEqual(
                cm.exception.reason_phrase,
                "Uniflow " + str(client_uniflow_id) + " does not exist",
            )

    def test_mp_handle_new_connection_id_initial_uniflow_id(self):
        client_msui = 1
        server_msui = 0
        client_uniflow_id = 0
        assert client_msui >= 1 > client_uniflow_id >= 0
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            buf = Buffer(capacity=100)
            buf.push_uint_var(client_uniflow_id)  # uniflow_id
            buf.push_uint_var(8)  # sequence_number
            buf.push_uint_var(0)  # retire_prior_to
            buf.push_uint8(8)
            buf.push_bytes(bytes(8))
            buf.push_bytes(bytes(16))
            buf.seek(0)

            # client receives MP_NEW_CONNECTION_ID for the initial uniflow
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_mp_new_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.MP_NEW_CONNECTION_ID,
                    buf,
                )
            self.assertEqual(
                cm.exception.error_code,
                QuicErrorCode.PROTOCOL_VIOLATION,
            )
            self.assertEqual(
                cm.exception.frame_type, QuicFrameType.MP_NEW_CONNECTION_ID
            )
            self.assertEqual(
                cm.exception.reason_phrase,
                "Uniflow "
                + str(client_uniflow_id)
                + " id not allowed for this frame type",
            )

    def test_mp_handle_retire_connection_id_invalid_uniflow_id(self):
        client_msui = 0
        server_msui = 1
        server_uniflow_id = 2
        assert server_uniflow_id > server_msui >= 1
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            buf = Buffer(capacity=100)
            buf.push_uint_var(server_uniflow_id)  # uniflow_id
            buf.push_uint_var(0)  # sequence_number
            buf.seek(0)

            # client receives MP_RETIRE_CONNECTION_ID for the current CID
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_mp_retire_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.MP_RETIRE_CONNECTION_ID,
                    buf,
                )
            self.assertEqual(cm.exception.error_code, QuicErrorCode.PROTOCOL_VIOLATION)
            self.assertEqual(
                cm.exception.frame_type, QuicFrameType.MP_RETIRE_CONNECTION_ID
            )
            self.assertEqual(
                cm.exception.reason_phrase,
                "Uniflow " + str(server_uniflow_id) + " does not exist",
            )
            for i in range(server_msui + 1):
                self.assertEqual(
                    sequence_numbers(client._receiving_uniflows[i].cid_available),
                    [0, 1, 2, 3, 4, 5, 6, 7],
                )

    def test_mp_retire_connection_id_initial_uniflow_id(self):
        client_msui = 0
        server_msui = 1
        server_uniflow_id = 0
        assert server_msui >= 1 > server_uniflow_id >= 0
        with client_and_server(
            client_options={"max_sending_uniflow_id": client_msui},
            server_options={"max_sending_uniflow_id": server_msui},
        ) as (client, server):
            buf = Buffer(capacity=100)
            buf.push_uint_var(server_uniflow_id)  # uniflow_id
            buf.push_uint_var(0)  # sequence_number
            buf.seek(0)

            # client receives MP_RETIRE_CONNECTION_ID for the initial uniflow
            with self.assertRaises(QuicConnectionError) as cm:
                client._handle_mp_retire_connection_id_frame(
                    client_receive_context(client),
                    QuicFrameType.MP_RETIRE_CONNECTION_ID,
                    buf,
                )
            self.assertEqual(
                cm.exception.error_code,
                QuicErrorCode.PROTOCOL_VIOLATION,
            )
            self.assertEqual(
                cm.exception.frame_type, QuicFrameType.MP_RETIRE_CONNECTION_ID
            )
            self.assertEqual(
                cm.exception.reason_phrase,
                "Uniflow "
                + str(server_uniflow_id)
                + " id not allowed for this frame type",
            )

    # Todo fix address tests
    def test_mp_remove_address(self):
        address_id = 1
        with client_and_server() as (client, server):
            server.add_address("2.3.4.5", 4444, IPVersion.IPV4, IFType.FIXED)
            server.add_address("2.3.4.5", 4455, IPVersion.IPV4, IFType.FIXED)
            self.assertEqual(transfer(server, client), 1)

            self.assertEqual(address_ids(client._remote_addresses.values()), [0, 1, 2])

            # the server removes the second address, REMOVE_ADDRESS is sent
            server.remove_address(address_id)
            self.assertEqual(transfer(server, client), 1)
            self.assertEqual(client._remote_addresses[address_id].is_enabled, False)
