import binascii
import logging
import os
import random
import socket
from collections import deque
from dataclasses import dataclass
from enum import Enum, IntEnum
from functools import partial
from typing import Any, Deque, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from .. import tls
from ..buffer import UINT_VAR_MAX, Buffer, BufferReadError, size_uint_var
from . import events
from .configuration import QuicConfiguration
from .crypto import CryptoError, CryptoPair, KeyUnavailableError
from .logger import QuicLoggerTrace
from .packet import (
    NON_ACK_ELICITING_FRAME_TYPES,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_ONE_RTT,
    PACKET_TYPE_RETRY,
    PACKET_TYPE_ZERO_RTT,
    PROBING_FRAME_TYPES,
    RETRY_INTEGRITY_TAG_SIZE,
    QuicErrorCode,
    QuicFrameType,
    QuicProtocolVersion,
    QuicStreamFrame,
    QuicTransportParameters,
    get_retry_integrity_tag,
    get_spin_bit,
    is_long_header,
    pull_ack_frame,
    pull_quic_header,
    pull_quic_transport_parameters,
    push_ack_frame,
    push_quic_transport_parameters,
)
from .packet_builder import (
    PACKET_MAX_SIZE,
    QuicDeliveryState,
    QuicPacketBuilder,
    QuicPacketBuilderStop,
    QuicSentPacket,
)
from .recovery import (
    K_GRANULARITY,
    QuicPacketRecovery,
    QuicReceivingPacketSpace,
    QuicSendingPacketSpace,
    discard_receiving_space,
)
from .stream import FinalSizeError, QuicStream

logger = logging.getLogger("quic")

CRYPTO_BUFFER_SIZE = 16384
EPOCH_SHORTCUTS = {
    "I": tls.Epoch.INITIAL,
    "H": tls.Epoch.HANDSHAKE,
    "0": tls.Epoch.ZERO_RTT,
    "1": tls.Epoch.ONE_RTT,
}
MAX_EARLY_DATA = 0xFFFFFFFF
SECRETS_LABELS = [
    [
        None,
        "CLIENT_EARLY_TRAFFIC_SECRET",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
    ],
    [
        None,
        None,
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_TRAFFIC_SECRET_0",
    ],
]
STREAM_FLAGS = 0x07

NetworkAddress = Any

# frame sizes
ACK_FRAME_CAPACITY = 64  # FIXME: this is arbitrary!
APPLICATION_CLOSE_FRAME_CAPACITY = 1 + 8 + 8  # + reason length
CONNECTION_LIMIT_FRAME_CAPACITY = 1 + 8
HANDSHAKE_DONE_FRAME_CAPACITY = 1
MAX_STREAM_DATA_FRAME_CAPACITY = 1 + 8 + 8
NEW_CONNECTION_ID_FRAME_CAPACITY = 1 + 8 + 8 + 1 + 20 + 16
PATH_CHALLENGE_FRAME_CAPACITY = 1 + 8
PATH_RESPONSE_FRAME_CAPACITY = 1 + 8
PING_FRAME_CAPACITY = 1
RESET_STREAM_CAPACITY = 1 + 8 + 8 + 8
RETIRE_CONNECTION_ID_CAPACITY = 1 + 8
STREAMS_BLOCKED_CAPACITY = 1 + 8
TRANSPORT_CLOSE_FRAME_CAPACITY = 1 + 8 + 8 + 8  # + reason length
MP_NEW_CONNECTION_ID_FRAME_CAPACITY = 1 + 8 + 8 + 8 + 1 + 20 + 16
MP_RETIRE_CONNECTION_ID_CAPACITY = 1 + 8 + 8
MP_ACK_FRAME_CAPACITY = 72  # fixme: this is arbitrary!
REMOVE_ADDRESS_CAPACITY = 1 + 1 + 8


def EPOCHS(shortcut: str) -> FrozenSet[tls.Epoch]:
    return frozenset(EPOCH_SHORTCUTS[i] for i in shortcut)


def dump_cid(cid: bytes) -> str:
    return binascii.hexlify(cid).decode("ascii")


def get_epoch(packet_type: int) -> tls.Epoch:
    if packet_type == PACKET_TYPE_INITIAL:
        return tls.Epoch.INITIAL
    elif packet_type == PACKET_TYPE_ZERO_RTT:
        return tls.Epoch.ZERO_RTT
    elif packet_type == PACKET_TYPE_HANDSHAKE:
        return tls.Epoch.HANDSHAKE
    else:
        return tls.Epoch.ONE_RTT


def stream_is_client_initiated(stream_id: int) -> bool:
    """
    Returns True if the stream is client initiated.
    """
    return not (stream_id & 1)


def stream_is_unidirectional(stream_id: int) -> bool:
    """
    Returns True if the stream is unidirectional.
    """
    return bool(stream_id & 2)


class Limit:
    def __init__(self, frame_type: int, name: str, value: int):
        self.frame_type = frame_type
        self.name = name
        self.sent = value
        self.used = 0
        self.value = value


class QuicConnectionError(Exception):
    def __init__(self, error_code: int, frame_type: int, reason_phrase: str):
        self.error_code = error_code
        self.frame_type = frame_type
        self.reason_phrase = reason_phrase

    def __str__(self) -> str:
        s = "Error: %d, reason: %s" % (self.error_code, self.reason_phrase)
        if self.frame_type is not None:
            s += ", frame_type: %s" % self.frame_type
        return s


class QuicConnectionAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: Any) -> Tuple[str, Any]:
        return "[%s] %s" % (self.extra["id"], msg), kwargs


@dataclass
class QuicConnectionId:
    cid: bytes
    sequence_number: Optional[int]
    stateless_reset_token: bytes = b""
    was_sent: bool = False


class QuicConnectionState(Enum):
    FIRSTFLIGHT = 0
    CONNECTED = 1
    CLOSING = 2
    DRAINING = 3
    TERMINATED = 4


class IPVersion(IntEnum):
    NONE = 0
    IPV4 = 4
    IPV6 = 6


class IFType(IntEnum):
    FIXED = 0
    WLAN = 1
    CELLULAR = 2
    OTHER = 3


class EndpointAddress:
    def __init__(
        self,
        *,
        address_id: Optional[int],
        ip_version: IPVersion,
        interface_type: IFType,
        ip_address: str,
        port: Optional[int],
        sequence_number: int,
    ) -> None:
        self.address_id: Optional[int] = address_id
        self.ip_version: IPVersion = ip_version
        self.interface_type: IFType = interface_type
        self.ip_address: str = ip_address
        self.port: Optional[int] = port

        self.was_sent: bool = False

        self.sequence_number: int = sequence_number
        self.is_enabled: bool = True

        # only used by initial uniflows
        self.bytes_received: int = 0
        self.bytes_sent: int = 0

    def can_send(self, size: int) -> bool:
        return (self.bytes_sent + size) <= 3 * self.bytes_received


def dump_address(addr: EndpointAddress) -> Tuple[str, Optional[int]]:
    return addr.ip_address, addr.port


END_STATES = frozenset(
    [
        QuicConnectionState.CLOSING,
        QuicConnectionState.DRAINING,
        QuicConnectionState.TERMINATED,
    ]
)


class UniflowState(Enum):
    UNUSED = 0
    ACTIVE = 1


class QuicReceivingUniflow:
    def __init__(
        self,
        *,
        uniflow_id: int,
        is_first: bool,
        configuration: QuicConfiguration,
    ) -> None:
        self.uniflow_id: int = uniflow_id
        self.cid_available: List[QuicConnectionId] = [
            QuicConnectionId(
                cid=os.urandom(configuration.connection_id_length),
                sequence_number=0,
                stateless_reset_token=os.urandom(16),
                was_sent=is_first,
            )
        ]
        self.cid: bytes = self.cid_available[0].cid
        self.cid_seq: int = 1
        self.packet_number: int = 0

        self.source_address: Optional[EndpointAddress] = None
        self.destination_address: Optional[EndpointAddress] = None

        self.remote_challenge: Optional[bytes] = None

        self.receiving_spaces: Dict[tls.Epoch, QuicReceivingPacketSpace] = {}

        self.perceived_remote_addresses: List[EndpointAddress] = []


class QuicSendingUniflow:
    def __init__(
        self,
        *,
        uniflow_id: int,
        is_first: bool,
        configuration: QuicConfiguration,
        congestion_windows_all: Dict[int, int],
        quic_logger: Optional[QuicLoggerTrace] = None,
    ) -> None:
        self.configuration: QuicConfiguration = configuration
        self.uniflow_id: int = uniflow_id
        self.cid: QuicConnectionId = QuicConnectionId(
            cid=os.urandom(configuration.connection_id_length),
            sequence_number=None,
        )
        self.cid_sequence_numbers: Set[int] = set([])
        if is_first:
            self.cid_sequence_numbers.add(0)
        self.cid_available: List[QuicConnectionId] = []
        self.token: bytes = b""
        self.retire_connection_ids: List[int] = []
        self.packet_number: int = 0

        self.state: UniflowState = UniflowState.UNUSED

        self.source_address: Optional[EndpointAddress] = None
        self.destination_address: Optional[EndpointAddress] = None

        self.path_is_validated: bool = False
        self.local_challenge: Optional[bytes] = None

        self.probe_pending = False
        self.loss_at: Optional[float] = None
        self.pacing_at: Optional[float] = None

        # Congestion controller
        # Performance metrics
        self.sending_spaces: Dict[tls.Epoch, QuicSendingPacketSpace] = {}
        self._quic_logger: Optional[QuicLoggerTrace] = quic_logger
        self._congestion_windows_all: Dict[int, int] = congestion_windows_all
        self.loss: QuicPacketRecovery = QuicPacketRecovery(
            initial_rtt=configuration.initial_rtt,
            # peer completed address validation is only applicable on uniflow 0, the other uniflows are not symmetrical
            peer_completed_address_validation=not configuration.is_client
            if is_first
            else True,
            cc_type=configuration.cc_type,
            uniflow_id=uniflow_id,
            congestion_windows_all=congestion_windows_all,
            quic_logger=quic_logger,
            send_probe=self.send_probe,
        )

    def send_probe(self):
        self.probe_pending = True

    def reset(self) -> None:
        self.state = UniflowState.UNUSED
        self.source_address = None
        self.destination_address = None
        self.path_is_validated = False
        self.local_challenge = None
        self.probe_pending = False
        self.loss_at = None
        self.pacing_at = None
        # reset congestion controller and performance metrics
        self.loss = QuicPacketRecovery(
            initial_rtt=self.configuration.initial_rtt,
            peer_completed_address_validation=not self.configuration.is_client,
            cc_type=self.configuration.cc_type,
            uniflow_id=self.uniflow_id,
            congestion_windows_all=self._congestion_windows_all,
            quic_logger=self._quic_logger,
            send_probe=self.send_probe,
        )
        self.loss.spaces = list(self.sending_spaces.values())


@dataclass
class QuicReceiveContext:
    epoch: tls.Epoch
    host_cid: bytes
    receiving_uniflow: QuicReceivingUniflow
    perceived_address: EndpointAddress
    quic_logger_frames: Optional[List[Any]]
    time: float


class QuicConnection:
    """
    A QUIC connection.

    The state machine is driven by three kinds of sources:

    - the API user requesting data to be send out (see :meth:`connect`,
      :meth:`reset_stream`, :meth:`send_ping`, :meth:`send_datagram_frame`
      and :meth:`send_stream_data`)
    - data being received from the network (see :meth:`receive_datagram`)
    - a timer firing (see :meth:`handle_timer`)

    :param configuration: The QUIC configuration to use.
    """

    def __init__(
        self,
        *,
        configuration: QuicConfiguration,
        original_destination_connection_id: Optional[bytes] = None,
        retry_source_connection_id: Optional[bytes] = None,
        session_ticket_fetcher: Optional[tls.SessionTicketFetcher] = None,
        session_ticket_handler: Optional[tls.SessionTicketHandler] = None,
    ) -> None:
        if configuration.is_client:
            assert (
                original_destination_connection_id is None
            ), "Cannot set original_destination_connection_id for a client"
            assert (
                retry_source_connection_id is None
            ), "Cannot set retry_source_connection_id for a client"
        else:
            assert (
                configuration.certificate is not None
            ), "SSL certificate is required for a server"
            assert (
                configuration.private_key is not None
            ), "SSL private key is required for a server"
            assert (
                original_destination_connection_id is not None
            ), "original_destination_connection_id is required for a server"

        # configuration
        self._configuration = configuration
        self._is_client = configuration.is_client

        self._ack_delay = K_GRANULARITY
        self._close_at: Optional[float] = None
        self._close_event: Optional[events.ConnectionTerminated] = None
        self._connect_called = False
        self._cryptos: Dict[tls.Epoch, CryptoPair] = {}
        self._crypto_buffers: Dict[tls.Epoch, Buffer] = {}
        self._crypto_streams: Dict[tls.Epoch, QuicStream] = {}
        self._events: Deque[events.QuicEvent] = deque()
        self._handshake_complete = False
        self._handshake_confirmed = False
        self._receiving_uniflows: Dict[int, QuicReceivingUniflow] = {
            0: QuicReceivingUniflow(
                uniflow_id=0,
                is_first=True,
                configuration=configuration,
            )
        }

        if self._is_client:
            self._receiving_uniflows[0].cid_available[0].stateless_reset_token = None

        self._congestion_windows_all: Dict[int, int] = {}

        self._sending_uniflows: Dict[int, QuicSendingUniflow] = {
            0: QuicSendingUniflow(
                uniflow_id=0,
                is_first=True,
                configuration=configuration,
                congestion_windows_all=self._congestion_windows_all,
            )
        }
        self._local_ack_delay_exponent = 3
        self._local_active_connection_id_limit = 8
        self._local_initial_source_connection_id = self._receiving_uniflows[0].cid
        self._local_max_data = Limit(
            frame_type=QuicFrameType.MAX_DATA,
            name="max_data",
            value=configuration.max_data,
        )
        self._local_max_stream_data_bidi_local = configuration.max_stream_data
        self._local_max_stream_data_bidi_remote = configuration.max_stream_data
        self._local_max_stream_data_uni = configuration.max_stream_data
        self._local_max_streams_bidi = Limit(
            frame_type=QuicFrameType.MAX_STREAMS_BIDI,
            name="max_streams_bidi",
            value=128,
        )
        self._local_max_streams_uni = Limit(
            frame_type=QuicFrameType.MAX_STREAMS_UNI, name="max_streams_uni", value=128
        )
        self._parameters_received = False
        self._quic_logger: Optional[QuicLoggerTrace] = None
        self._remote_ack_delay_exponent = 3
        self._remote_active_connection_id_limit = 2
        self._remote_idle_timeout = 0.0  # seconds
        self._remote_max_data = 0
        self._remote_max_data_used = 0
        self._remote_max_datagram_frame_size: Optional[int] = None
        self._remote_max_stream_data_bidi_local = 0
        self._remote_max_stream_data_bidi_remote = 0
        self._remote_max_stream_data_uni = 0
        self._remote_max_streams_bidi = 0
        self._remote_max_streams_uni = 0
        self._retry_count = 0
        self._retry_source_connection_id = retry_source_connection_id
        self._spin_bit = False
        self._spin_highest_pn = 0
        self._state = QuicConnectionState.FIRSTFLIGHT
        self._streams: Dict[int, QuicStream] = {}
        self._streams_blocked_bidi: List[QuicStream] = []
        self._streams_blocked_uni: List[QuicStream] = []
        self._version: Optional[int] = None
        self._version_negotiation_count = 0

        if self._is_client:
            self._original_destination_connection_id = self._sending_uniflows[0].cid.cid
        else:
            self._original_destination_connection_id = (
                original_destination_connection_id
            )

        self._max_sending_uniflows_id = configuration.max_sending_uniflow_id
        self._peer_mp_support = False
        self._peer_max_sending_uniflows_id = 0

        self._builder_manager = BuilderManager()

        self._local_addresses: Dict[int, EndpointAddress] = {}
        # Copy the addresses shared in the configuration
        for i in range(len(configuration.local_addresses)):
            laddr = configuration.local_addresses[i]
            addr = EndpointAddress(
                address_id=i,
                ip_version=laddr[1],
                interface_type=laddr[2],
                ip_address=laddr[0],
                port=(laddr[3] if len(laddr) >= 4 else None),
                sequence_number=0,
            )
            self._local_addresses[i] = addr

        self._remote_addresses: Dict[int, EndpointAddress] = {}
        self._perceived_remote_addresses: List[EndpointAddress] = []

        self._uniflows_seq = -1
        self._remote_uniflows_seq = -1

        # logging
        self._logger = QuicConnectionAdapter(
            logger, {"id": dump_cid(self._original_destination_connection_id)}
        )
        if configuration.quic_logger:
            self._quic_logger = configuration.quic_logger.start_trace(
                is_client=configuration.is_client,
                odcid=self._original_destination_connection_id,
            )

        # things to send
        self._close_pending = False
        self._datagrams_pending: Deque[bytes] = deque()
        self._handshake_done_pending = False
        self._ping_pending: List[int] = []
        self._streams_blocked_pending = False
        self._removed_addresses: List[int] = []
        self._uniflows_pending = False

        # callbacks
        self._session_ticket_fetcher = session_ticket_fetcher
        self._session_ticket_handler = session_ticket_handler

        self._MP = False  # Patch for pquic connection

        # frame handlers
        self.__frame_handlers = {
            0x00: (self._handle_padding_frame, EPOCHS("IH01")),
            0x01: (self._handle_ping_frame, EPOCHS("IH01")),
            0x02: (self._handle_ack_frame, EPOCHS("IH1")),
            0x03: (self._handle_ack_frame, EPOCHS("IH1")),
            0x04: (self._handle_reset_stream_frame, EPOCHS("01")),
            0x05: (self._handle_stop_sending_frame, EPOCHS("01")),
            0x06: (self._handle_crypto_frame, EPOCHS("IH1")),
            0x07: (self._handle_new_token_frame, EPOCHS("1")),
            0x08: (self._handle_stream_frame, EPOCHS("01")),
            0x09: (self._handle_stream_frame, EPOCHS("01")),
            0x0A: (self._handle_stream_frame, EPOCHS("01")),
            0x0B: (self._handle_stream_frame, EPOCHS("01")),
            0x0C: (self._handle_stream_frame, EPOCHS("01")),
            0x0D: (self._handle_stream_frame, EPOCHS("01")),
            0x0E: (self._handle_stream_frame, EPOCHS("01")),
            0x0F: (self._handle_stream_frame, EPOCHS("01")),
            0x10: (self._handle_max_data_frame, EPOCHS("01")),
            0x11: (self._handle_max_stream_data_frame, EPOCHS("01")),
            0x12: (self._handle_max_streams_bidi_frame, EPOCHS("01")),
            0x13: (self._handle_max_streams_uni_frame, EPOCHS("01")),
            0x14: (self._handle_data_blocked_frame, EPOCHS("01")),
            0x15: (self._handle_stream_data_blocked_frame, EPOCHS("01")),
            0x16: (self._handle_streams_blocked_frame, EPOCHS("01")),
            0x17: (self._handle_streams_blocked_frame, EPOCHS("01")),
            0x18: (self._handle_new_connection_id_frame, EPOCHS("01")),
            0x19: (self._handle_retire_connection_id_frame, EPOCHS("01")),
            0x1A: (self._handle_path_challenge_frame, EPOCHS("01")),
            0x1B: (self._handle_path_response_frame, EPOCHS("01")),
            0x1C: (self._handle_connection_close_frame, EPOCHS("IH01")),
            0x1D: (self._handle_connection_close_frame, EPOCHS("01")),
            0x1E: (self._handle_handshake_done_frame, EPOCHS("1")),
            0x30: (self._handle_datagram_frame, EPOCHS("01")),
            0x31: (self._handle_datagram_frame, EPOCHS("01")),
            0x40: (self._handle_mp_new_connection_id_frame, EPOCHS("1")),
            0x41: (self._handle_mp_retire_connection_id_frame, EPOCHS("1")),
            0x42: (self._handle_mp_ack_frame, EPOCHS("1")),
            0x43: (self._handle_mp_ack_frame, EPOCHS("1")),
            0x44: (self._handle_add_address_frame, EPOCHS("1")),
            0x45: (self._handle_remove_address_frame, EPOCHS("1")),
            0x46: (self._handle_uniflows_frame, EPOCHS("1")),
        }

    @property
    def configuration(self) -> QuicConfiguration:
        return self._configuration

    @property
    def original_destination_connection_id(self) -> bytes:
        return self._original_destination_connection_id

    def change_connection_id(self, uniflow_id: int) -> None:
        """
        Switch to the next available connection ID and retire
        the previous one.

        After calling this method call :meth:`datagrams_to_send` to retrieve data
        which needs to be sent.
        """

        # Old version for normal connections
        # uniflow = self._sending_uniflows[uniflow_id]
        # if uniflow.cid_available:
        #     # retire previous CID
        #     self._retire_peer_cid(uniflow_id, uniflow.cid)

        #     # assign new CID
        #     self._consume_peer_cid(uniflow_id)

        # Patch version for pquic connection

        uniflow = self._sending_uniflows[uniflow_id]
        # retire previous CID
        self._retire_peer_cid(uniflow_id, uniflow.cid)

        if uniflow.cid_available:
            # assign new CID
            self._consume_peer_cid(uniflow_id)
        else:
            # generate random CID that isn't an actual CID
            uniflow.cid = QuicConnectionId(
                cid=os.urandom(self.configuration.connection_id_length),
                sequence_number=None,
            )

    def add_address(
        self,
        ip_address: str,
        port: Optional[int],
        ip_version: IPVersion,
        interface_type: IFType,
    ) -> None:
        """
        Add a new address for the connection to communicate over.

        After calling this method call :meth:`datagrams_to_send` to retrieve data
        which needs to be sent.
        """
        address_id = -1
        for addr in self._local_addresses.values():
            # check for already existing addresses
            if addr.ip_address == ip_address and addr.port == port:
                return
            if addr.address_id > address_id:
                address_id = addr.address_id
        address_id += 1
        self._local_addresses[address_id] = EndpointAddress(
            address_id=len(self._local_addresses),
            ip_version=ip_version,
            interface_type=interface_type,
            ip_address=ip_address,
            port=port,
            sequence_number=0,
        )

    def remove_address(self, address_id: int):
        """
        Remove an address from the connection.

        After calling this method call :meth:`datagrams_to_send` to retrieve data
        which needs to be sent.
        """
        if address_id in self._local_addresses.keys():
            self._local_addresses[address_id].is_enabled = False
            self._local_addresses[address_id].sequence_number += 1
            self._removed_addresses.append(address_id)

            # reset uniflows that use this address
            for suniflow in self._sending_uniflows.values():
                if suniflow.source_address.address_id == address_id:
                    suniflow.reset()

            # write uniflows frame to communicate state
            if not self._uniflows_pending:
                self._uniflows_seq += 1
                self._uniflows_pending = True

    def close(
        self,
        error_code: int = QuicErrorCode.NO_ERROR,
        frame_type: Optional[int] = None,
        reason_phrase: str = "",
    ) -> None:
        """
        Close the connection.

        :param error_code: An error code indicating why the connection is
                           being closed.
        :param frame_type: Optional: the type of the frame
        :param reason_phrase: A human-readable explanation of why the
                              connection is being closed.
        """
        if self._state not in END_STATES:
            self._close_event = events.ConnectionTerminated(
                error_code=error_code,
                frame_type=frame_type,
                reason_phrase=reason_phrase,
            )
            self._close_pending = True

    def connect(
        self, addr: NetworkAddress, local_addr: NetworkAddress, now: float
    ) -> None:
        """
        Initiate the TLS handshake.

        This method can only be called for clients and a single time.

        After calling this method call :meth:`datagrams_to_send` to retrieve data
        which needs to be sent.

        :param addr: The network address of the remote peer.
        :param local_addr: The network address of the local peer.
        :param now: The current time.
        """
        assert (
            self._is_client and not self._connect_called
        ), "connect() can only be called for clients and a single time"
        self._connect_called = True

        perceived_remote_address = EndpointAddress(
            address_id=0,
            ip_address=addr[0],
            port=addr[1],
            ip_version=IPVersion.NONE,
            interface_type=IFType.OTHER,
            sequence_number=0,
        )
        perceived_local_address = self._find_local_address(local_addr)
        assert perceived_local_address is not None, "local address must be known"

        self._perceived_remote_addresses = [perceived_remote_address]
        perceived_remote_address.address_id = 0
        self._remote_addresses[0] = perceived_remote_address
        self._set_initial_address(perceived_local_address)
        self._version = self._configuration.supported_versions[0]
        isenduniflow = self._sending_uniflows[0]
        isenduniflow.state = UniflowState.ACTIVE
        isenduniflow.source_address = perceived_local_address
        isenduniflow.destination_address = perceived_remote_address
        isenduniflow.path_is_validated = True

        irecvuniflow = self._receiving_uniflows[0]
        irecvuniflow.source_address = perceived_remote_address
        irecvuniflow.destination_address = perceived_local_address

        """print(
            "CONNECT set sending uniflow 0 source address: ",
            (dump_address(isenduniflow.source_address)),
            "\nCONNECT set sending uniflow 0 destination address: ",
            (dump_address(isenduniflow.destination_address)),
            "\nCONNECT set receiving uniflow 0 source address: ",
            (dump_address(irecvuniflow.source_address)),
            "\nCONNECT set receiving uniflow 0 destination address: ",
            (dump_address(irecvuniflow.destination_address)),
        )"""
        self._connect(now=now)

    def datagrams_to_send(
        self, now: float
    ) -> List[Tuple[bytes, NetworkAddress, NetworkAddress]]:
        """
        Return a list of `(data, addr)` tuples of datagrams which need to be
        sent, and the network address to which they need to be sent.

        After calling this method call :meth:`get_timer` to know when the next
        timer needs to be set.

        :param now: The current time.
        """

        ret: List[Tuple[bytes, NetworkAddress, NetworkAddress]] = []

        if self._state in END_STATES:
            return ret

        # split the uniflows in active ones and unused, unbound ones
        active_uniflows = []
        unused_uniflows = []
        for suniflow in self._sending_uniflows.values():
            if suniflow.state == UniflowState.ACTIVE:
                active_uniflows.append(suniflow)
            elif (
                suniflow.state == UniflowState.UNUSED
                and suniflow.source_address is None
                and suniflow.destination_address is None
                # and len(suniflow.cid_available) > 0  # Disable for PQUIC connection
                and len(suniflow.cid_available) >= 0  # Patch for pquic connection
                and suniflow.cid.sequence_number is not None
            ):
                unused_uniflows.append(suniflow)

        # handle closing
        if self._close_pending:
            selected_uniflow = random.choice(active_uniflows)
            # print("closing with uniflow", selected_uniflow.uniflow_id)
            builder = QuicPacketBuilder(
                host_cid=self._receiving_uniflows[0].cid,
                is_client=self._is_client,
                packet_number=selected_uniflow.packet_number,
                peer_cid=selected_uniflow.cid.cid,
                peer_token=selected_uniflow.token,
                quic_logger=self._quic_logger,
                spin_bit=self._spin_bit,
                version=self._version,
            )

            # write connection close for valid epoch
            for epoch, packet_type in (
                (tls.Epoch.ONE_RTT, PACKET_TYPE_ONE_RTT),
                (tls.Epoch.HANDSHAKE, PACKET_TYPE_HANDSHAKE),
                (tls.Epoch.INITIAL, PACKET_TYPE_INITIAL),
            ):
                crypto = self._cryptos[epoch]
                if crypto.send.is_valid():
                    builder.start_packet(packet_type, crypto)
                    self._write_connection_close_frame(
                        builder=builder,
                        epoch=epoch,
                        error_code=self._close_event.error_code,
                        frame_type=self._close_event.frame_type,
                        reason_phrase=self._close_event.reason_phrase,
                    )
                    self._close_pending = False
                    break
            self._close_begin(is_initiator=True, now=now)
            datagrams, packets = builder.flush()

            if datagrams:
                selected_uniflow.packet_number = builder.packet_number

                # register packets
                self._register_packets(packets, selected_uniflow, now)

            # return datagrams to send and the destination network address
            ret.extend(self._couple_datagrams_to_address(datagrams, selected_uniflow))

        else:  # handle normal communication
            # bind unused uniflows to addresses
            if (
                self._state == QuicConnectionState.CONNECTED
                and self._MP  # Patch for pquic connection
                # and len(self._remote_addresses.keys()) > 1  # Disable for pquic connection
            ):
                for uuniflow in unused_uniflows:
                    # set random source/destination addresses
                    rsaid = random.choice(list(self._local_addresses.keys()))
                    rsaid = uuniflow.uniflow_id  # Patch for pquic connection
                    source_address = self._local_addresses[rsaid]
                    rdaid = random.choice(list(self._remote_addresses.keys()))
                    rdaid = 0  # Patch for pquic connection
                    destination_address = self._remote_addresses[rdaid]

                    uuniflow.source_address = source_address
                    uuniflow.destination_address = destination_address

                    """print(
                        "set sending uniflow "
                        + str(uuniflow.uniflow_id)
                        + " source address: ",
                        (dump_address(uuniflow.source_address)),
                        "\nset sending uniflow "
                        + str(uuniflow.uniflow_id)
                        + " destination address: ",
                        (dump_address(uuniflow.destination_address)),
                    )"""

                    builder = QuicPacketBuilder(
                        host_cid=self._receiving_uniflows[0].cid,
                        is_client=self._is_client,
                        packet_number=uuniflow.packet_number,
                        peer_cid=uuniflow.cid.cid,
                        peer_token=uuniflow.token,
                        quic_logger=self._quic_logger,
                        spin_bit=self._spin_bit,
                        version=self._version,
                    )

                    # write path challenge frame
                    try:
                        crypto = self._cryptos[tls.Epoch.ONE_RTT]
                        packet_type = PACKET_TYPE_ONE_RTT

                        builder.start_packet(packet_type, crypto)
                        # print("sending PATH_CHALLENGE over uniflow", uuniflow.uniflow_id)
                        uuniflow.local_challenge = os.urandom(8)
                        self._write_path_challenge_frame(
                            builder=builder,
                            challenge=uuniflow.local_challenge,
                            uniflow_id=uuniflow.uniflow_id,
                        )
                    except QuicPacketBuilderStop:
                        pass

                    datagrams, packets = builder.flush()

                    if datagrams:
                        uuniflow.packet_number = builder.packet_number

                        # register packets
                        self._register_packets(packets, uuniflow, now)

                    # return datagrams to send and the destination network address
                    ret_unused = self._couple_datagrams_to_address(datagrams, uuniflow)
                    ret.extend(ret_unused)

            # use active sending uniflows
            builders: Dict[int, Tuple[QuicSendingUniflow, QuicPacketBuilder]] = {}
            for auniflow in active_uniflows:
                builder = QuicPacketBuilder(
                    host_cid=self._receiving_uniflows[0].cid,
                    is_client=self._is_client,
                    packet_number=auniflow.packet_number,
                    peer_cid=auniflow.cid.cid,
                    peer_token=auniflow.token,
                    quic_logger=self._quic_logger,
                    spin_bit=self._spin_bit,
                    version=self._version,
                )

                # congestion control
                builder.max_flight_bytes = (
                    auniflow.loss.congestion_window - auniflow.loss.bytes_in_flight
                )
                if (
                    auniflow.probe_pending
                    and builder.max_flight_bytes < PACKET_MAX_SIZE
                ):
                    builder.max_flight_bytes = PACKET_MAX_SIZE

                # limit data on un-validated network paths
                if auniflow.uniflow_id == 0 and not auniflow.path_is_validated:
                    builder.max_total_bytes = (
                        auniflow.destination_address.bytes_received * 3
                        - auniflow.destination_address.bytes_sent
                    )

                builders[auniflow.uniflow_id] = (auniflow, builder)

            try:
                if not self._handshake_confirmed:
                    for epoch in [tls.Epoch.INITIAL, tls.Epoch.HANDSHAKE]:
                        self._write_handshake(builders[0][1], epoch, now)
                builders = self._write_application(builders, now)
            except QuicPacketBuilderStop:
                print("exception during PacketBuilder")
                pass

            # flush all builders
            for uniflow_id, (auniflow, builder) in builders.items():
                datagrams, packets = builder.flush()

                if datagrams:
                    auniflow.packet_number = builder.packet_number

                    # register packets
                    self._register_packets(packets, auniflow, now)

                # return datagrams to send and the destination network address
                ret.extend(self._couple_datagrams_to_address(datagrams, auniflow))
        return ret

    def _register_packets(
        self,
        packets: List[QuicSentPacket],
        selected_uniflow: QuicSendingUniflow,
        now: float,
    ) -> None:
        sent_handshake = False
        for packet in packets:
            packet.sent_time = now
            space = selected_uniflow.sending_spaces[packet.epoch]
            selected_uniflow.loss.on_packet_sent(packet=packet, space=space)
            if packet.epoch == tls.Epoch.HANDSHAKE:
                sent_handshake = True

            # log packet
            # print("su", selected_uniflow.uniflow_id, "packet", packet.packet_number)
            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="transport",
                    event="packet_sent",
                    data={
                        "packet_type": self._quic_logger.packet_type(
                            packet.packet_type
                        ),
                        "header": {
                            "packet_number": str(
                                (
                                    packet.packet_number
                                    + selected_uniflow.uniflow_id * 100000
                                )
                            ),
                            "packet_size": packet.sent_bytes,
                            "scid": dump_cid(self._receiving_uniflows[0].cid)
                            if is_long_header(packet.packet_type)
                            else "",
                            "dcid": dump_cid(selected_uniflow.cid.cid),
                        },
                        "frames": packet.quic_logger_frames,
                    },
                )

        # check if we can discard initial keys
        if sent_handshake and self._is_client and selected_uniflow.uniflow_id == 0:
            self._discard_epoch(tls.Epoch.INITIAL)

    def _couple_datagrams_to_address(
        self, datagrams: List[bytes], selected_uniflow: QuicSendingUniflow
    ) -> List[Tuple[bytes, NetworkAddress, NetworkAddress]]:
        ret = []
        for datagram in datagrams:
            byte_length = len(datagram)
            network_path = selected_uniflow.destination_address
            network_path.bytes_sent += byte_length

            ret.append(
                (
                    datagram,
                    (
                        selected_uniflow.destination_address.ip_address,
                        selected_uniflow.destination_address.port,
                    ),
                    (
                        selected_uniflow.source_address.ip_address,
                        selected_uniflow.source_address.port,
                    ),
                )
            )
            # print("sending on uniflow", selected_uniflow.uniflow_id, "from", ret[-1][2], "to", ret[-1][1])

            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="transport",
                    event="datagrams_sent",
                    data={"byte_length": byte_length, "count": 1},
                )
        return ret

    def get_next_available_stream_id(self, is_unidirectional=False) -> int:
        """
        Return the stream ID for the next stream created by this endpoint.
        """
        stream_id = (int(is_unidirectional) << 1) | int(not self._is_client)
        while stream_id in self._streams:
            stream_id += 4
        return stream_id

    def get_timer(self) -> Optional[float]:
        """
        Return the time at which the timer should fire or None if no timer is needed.
        """
        timer_at = self._close_at
        if self._state not in END_STATES:
            # ack timer
            for runiflow in self._receiving_uniflows.values():
                for space in runiflow.receiving_spaces.values():
                    if space.ack_at is not None and space.ack_at < timer_at:
                        timer_at = space.ack_at
                        # print("ack timer", runiflow.uniflow_id)

            # loss detection timer
            for suniflow in self._sending_uniflows.values():
                suniflow.loss_at = suniflow.loss.get_loss_detection_time()
                if suniflow.loss_at is not None and suniflow.loss_at < timer_at:
                    timer_at = suniflow.loss_at
                    # print("loss timer", suniflow.uniflow_id)

                # pacing timer
                if suniflow.pacing_at is not None and suniflow.pacing_at < timer_at:
                    timer_at = suniflow.pacing_at
                    # print("pacing timer", suniflow.uniflow_id)

        return timer_at

    def handle_timer(self, now: float) -> None:
        """
        Handle the timer.

        After calling this method call :meth:`datagrams_to_send` to retrieve data
        which needs to be sent.

        :param now: The current time.
        """
        # print("timer being handled")
        # end of closing period or idle timeout
        if now >= self._close_at:
            if self._close_event is None:
                self._close_event = events.ConnectionTerminated(
                    error_code=QuicErrorCode.INTERNAL_ERROR,
                    frame_type=None,
                    reason_phrase="Idle timeout",
                )
            # print("closing")
            self._close_end()
            return

        # loss detection timeout
        for suniflow in self._sending_uniflows.values():
            if suniflow.loss_at is not None and now >= suniflow.loss_at:
                # print("timeout", suniflow.uniflow_id)
                self._logger.debug(
                    "uniflow " + str(suniflow.uniflow_id) + " Loss detection triggered"
                )
                suniflow.loss.on_loss_detection_timeout(now=now)

    def next_event(self) -> Optional[events.QuicEvent]:
        """
        Retrieve the next event from the event buffer.

        Returns `None` if there are no buffered events.
        """
        try:
            return self._events.popleft()
        except IndexError:
            return None

    def receive_datagram(
        self, data: bytes, addr: NetworkAddress, local_addr: NetworkAddress, now: float
    ) -> None:
        """
        Handle an incoming datagram.

        After calling this method call :meth:`datagrams_to_send` to retrieve data
        which needs to be sent.

        :param data: The datagram which was received.
        :param addr: The network address from which the datagram was received.
        :param local_addr: The network address on which the datagram was received
        :param now: The current time.
        """
        # print("datagram received on connection")
        # stop handling packets when closing
        if self._state in END_STATES:
            return

        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="transport",
                event="datagrams_received",
                data={"byte_length": len(data), "count": 1},
            )

        buf = Buffer(data=data)
        while not buf.eof():
            start_off = buf.tell()
            try:
                header = pull_quic_header(
                    buf, host_cid_length=self._configuration.connection_id_length
                )
            except ValueError:
                return

            # check destination CID matches
            destination_cid_seq: Optional[int] = None
            srecvuniflow: QuicReceivingUniflow = self._receiving_uniflows[0]
            for uniflow in self._receiving_uniflows.values():
                for connection_id in uniflow.cid_available:
                    if header.destination_cid == connection_id.cid:
                        destination_cid_seq = connection_id.sequence_number
                        srecvuniflow = uniflow
                        break
            # print("receiving on uniflow", srecvuniflow.uniflow_id, "from", addr, "to", local_addr)
            if self._is_client and destination_cid_seq is None:
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={"trigger": "unknown_connection_id"},
                    )
                return

            # check protocol version
            if (
                self._is_client
                and self._state == QuicConnectionState.FIRSTFLIGHT
                and header.version == QuicProtocolVersion.NEGOTIATION
                and not self._version_negotiation_count
            ):
                # version negotiation
                # print("handling VERSION NEGOTIATION")
                versions = []
                while not buf.eof():
                    versions.append(buf.pull_uint32())
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_received",
                        data={
                            "packet_type": "version_negotiation",
                            "header": {
                                "scid": dump_cid(header.source_cid),
                                "dcid": dump_cid(header.destination_cid),
                            },
                            "frames": [],
                        },
                    )
                if self._version in versions:
                    self._logger.warning(
                        "Version negotiation packet contains %s" % self._version
                    )
                    return
                common = set(self._configuration.supported_versions).intersection(
                    versions
                )
                if not common:
                    self._logger.error("Could not find a common protocol version")
                    self._close_event = events.ConnectionTerminated(
                        error_code=QuicErrorCode.INTERNAL_ERROR,
                        frame_type=None,
                        reason_phrase="Could not find a common protocol version",
                    )
                    self._close_end()
                    return
                self._sending_uniflows[0].packet_number = 0
                self._version = QuicProtocolVersion(max(common))
                self._version_negotiation_count += 1
                self._logger.info("Retrying with %s", self._version)
                self._connect(now=now)
                return
            elif (
                header.version is not None
                and header.version not in self._configuration.supported_versions
            ):
                # unsupported version
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={"trigger": "unsupported_version"},
                    )
                return

            if self._is_client and header.packet_type == PACKET_TYPE_RETRY:
                # calculate retry integrity tag
                integrity_tag = get_retry_integrity_tag(
                    buf.data_slice(start_off, buf.tell() - RETRY_INTEGRITY_TAG_SIZE),
                    self._sending_uniflows[0].cid.cid,
                    version=header.version,
                )

                if (
                    header.destination_cid == self._receiving_uniflows[0].cid
                    and header.integrity_tag == integrity_tag
                    and not self._retry_count
                ):
                    if self._quic_logger is not None:
                        self._quic_logger.log_event(
                            category="transport",
                            event="packet_received",
                            data={
                                "packet_type": "retry",
                                "header": {
                                    "scid": dump_cid(header.source_cid),
                                    "dcid": dump_cid(header.destination_cid),
                                },
                                "frames": [],
                            },
                        )
                    # print("handling RETRY")
                    self._sending_uniflows[0].cid.cid = header.source_cid
                    self._sending_uniflows[0].token = header.token
                    self._retry_count += 1
                    self._retry_source_connection_id = header.source_cid
                    self._logger.info(
                        "Retrying with token (%d bytes)" % len(header.token)
                    )
                    self._connect(now=now)
                return

            # get the info of the addresses
            perceived_remote_address = self._find_address(addr)
            perceived_local_address = self._find_local_address(local_addr)
            assert perceived_local_address is not None, "local address must be known"

            # server initialization
            if not self._is_client and self._state == QuicConnectionState.FIRSTFLIGHT:
                assert (
                    header.packet_type == PACKET_TYPE_INITIAL
                ), "first packet must be INITIAL"

                self._perceived_remote_addresses = [perceived_remote_address]
                perceived_remote_address.address_id = 0
                self._remote_addresses[0] = perceived_remote_address
                self._set_initial_address(perceived_local_address)
                self._version = QuicProtocolVersion(header.version)

                isenduniflow = self._sending_uniflows[0]
                isenduniflow.state = UniflowState.ACTIVE
                isenduniflow.source_address = perceived_local_address
                isenduniflow.destination_address = perceived_remote_address

                irecvuniflow = self._receiving_uniflows[0]
                irecvuniflow.source_address = perceived_remote_address
                irecvuniflow.destination_address = perceived_local_address

                """print(
                    "INITIALIZE set sending uniflow 0 source address: ",
                    (dump_address(isenduniflow.source_address)),
                    "\nINITIALIZE set sending uniflow 0 destination address: ",
                    (dump_address(isenduniflow.destination_address)),
                    "\nINITIALIZE set receiving uniflow 0 source address: ",
                    (dump_address(irecvuniflow.source_address)),
                    "\nINITIALIZE set receiving uniflow 0 destination address: ",
                    (dump_address(irecvuniflow.destination_address)),
                )"""
                self._initialize(header.destination_cid)

            # determine crypto and packet space
            epoch = get_epoch(header.packet_type)
            crypto = self._cryptos[epoch]
            spaces = srecvuniflow.receiving_spaces
            if epoch == tls.Epoch.ZERO_RTT:
                space = spaces[tls.Epoch.ONE_RTT]
            else:
                space = spaces[epoch]

            # decrypt packet
            encrypted_off = buf.tell() - start_off
            end_off = buf.tell() + header.rest_length
            buf.seek(end_off)

            try:
                plain_header, plain_payload, packet_number = crypto.decrypt_packet(
                    data[start_off:end_off], encrypted_off, space.expected_packet_number
                )
                # print("Packet number", packet_number)
            except KeyUnavailableError as exc:
                print("key unavailable")
                self._logger.debug(exc)
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={"trigger": "key_unavailable"},
                    )
                continue
            except CryptoError as exc:
                print("decrypt error:", exc.args[0])
                self._logger.debug(exc)
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={"trigger": "payload_decrypt_error"},
                    )
                continue

            # check reserved bits
            if header.is_long_header:
                reserved_mask = 0x0C
            else:
                reserved_mask = 0x18
            if plain_header[0] & reserved_mask:
                self.close(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=None,
                    reason_phrase="Reserved bits must be zero",
                )
                return

            # raise expected packet number
            if packet_number > space.expected_packet_number:
                space.expected_packet_number = packet_number + 1

            # log packet
            quic_logger_frames: Optional[List[Dict]] = None
            if self._quic_logger is not None:
                quic_logger_frames = []
                self._quic_logger.log_event(
                    category="transport",
                    event="packet_received",
                    data={
                        "packet_type": self._quic_logger.packet_type(
                            header.packet_type
                        ),
                        "header": {
                            "packet_number": str(
                                (packet_number + srecvuniflow.uniflow_id * 100000)
                            ),
                            "packet_size": end_off - start_off,
                            "dcid": dump_cid(header.destination_cid),
                            "scid": dump_cid(header.source_cid),
                        },
                        "frames": quic_logger_frames,
                    },
                )

            # discard initial keys and packet space
            if not self._is_client and epoch == tls.Epoch.HANDSHAKE:
                self._discard_epoch(tls.Epoch.INITIAL)

            # update state so that the cid of sending uniflow 0 equals the cid chosen by the client
            if self._sending_uniflows[0].cid.sequence_number is None:
                self._sending_uniflows[0].cid.cid = header.source_cid
                self._sending_uniflows[0].cid.sequence_number = 0

            if self._state == QuicConnectionState.FIRSTFLIGHT:
                self._set_state(QuicConnectionState.CONNECTED)

            # update spin bit
            if not header.is_long_header and packet_number > self._spin_highest_pn:
                spin_bit = get_spin_bit(plain_header[0])
                if self._is_client:
                    self._spin_bit = not spin_bit
                else:
                    self._spin_bit = spin_bit
                self._spin_highest_pn = packet_number

                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="connectivity",
                        event="spin_bit_updated",
                        data={"state": self._spin_bit},
                    )

            # handle payload
            context = QuicReceiveContext(
                epoch=epoch,
                host_cid=header.destination_cid,
                receiving_uniflow=srecvuniflow,
                perceived_address=perceived_remote_address,
                quic_logger_frames=quic_logger_frames,
                time=now,
            )
            is_ack_eliciting = False
            is_probing = False
            try:
                is_ack_eliciting, is_probing = self._payload_received(
                    context, plain_payload
                )
            except QuicConnectionError as exc:
                self._logger.warning(exc)
                self.close(
                    error_code=exc.error_code,
                    frame_type=exc.frame_type,
                    reason_phrase=exc.reason_phrase,
                )
            if self._state in END_STATES or self._close_pending:
                return

            # update idle timeout
            self._close_at = now + self._configuration.idle_timeout

            # handle migration
            if (
                not self._is_client
                and context.host_cid != srecvuniflow.cid
                and epoch == tls.Epoch.ONE_RTT
            ):
                self._logger.debug(
                    "Peer switching to CID %s (%d)",
                    dump_cid(context.host_cid),
                    destination_cid_seq,
                )
                srecvuniflow.cid = context.host_cid
                self.change_connection_id(srecvuniflow.uniflow_id)

            # update network path
            if (
                epoch == tls.Epoch.HANDSHAKE
                and not self._sending_uniflows[0].path_is_validated
            ):
                self._logger.debug(
                    "Network path %s validated by handshake",
                    (dump_address(perceived_remote_address)),
                )
                self._sending_uniflows[0].path_is_validated = True

            if perceived_remote_address not in self._perceived_remote_addresses:
                self._perceived_remote_addresses.append(perceived_remote_address)
            if perceived_remote_address not in srecvuniflow.perceived_remote_addresses:
                srecvuniflow.perceived_remote_addresses.append(perceived_remote_address)

            perceived_remote_address.bytes_received += end_off - start_off

            # check if changes were made to the 4-tuple
            # Todo: handle section 9.5
            if srecvuniflow.source_address != perceived_remote_address:
                if srecvuniflow.source_address is None:
                    # print("RECEIVE Uniflow " + str(srecvuniflow.uniflow_id) + " detected new source address")
                    srecvuniflow.source_address = perceived_remote_address
                else:
                    # print("RECEIVE Uniflow " + str(srecvuniflow.uniflow_id) + " detected source address change")
                    idx = srecvuniflow.perceived_remote_addresses.index(
                        perceived_remote_address
                    )
                    if (
                        idx
                        and not is_probing
                        and packet_number > space.largest_received_packet
                    ):
                        self._logger.debug(
                            "Network path %s promoted",
                            (dump_address(perceived_remote_address)),
                        )
                        srecvuniflow.perceived_remote_addresses.pop(idx)
                        srecvuniflow.perceived_remote_addresses.insert(
                            0, perceived_remote_address
                        )
                        srecvuniflow.source_address = perceived_remote_address
                        if srecvuniflow.uniflow_id == 0:
                            isenduniflow = self._sending_uniflows[0]
                            isenduniflow.destination_address = perceived_remote_address
                            isenduniflow.path_is_validated = False

            if srecvuniflow.destination_address != perceived_local_address:
                if srecvuniflow.destination_address is None:
                    # print("RECEIVE Uniflow " + str(srecvuniflow.uniflow_id) + " detected new destination address")
                    pass
                else:
                    # print("RECEIVE Uniflow " + str(srecvuniflow.uniflow_id) + " detected destination address change")
                    pass
                srecvuniflow.destination_address = perceived_local_address

            # record packet as received
            if not space.discarded:
                if packet_number > space.largest_received_packet:
                    space.largest_received_packet = packet_number
                    space.largest_received_time = now
                space.ack_queue.add(packet_number)
                if is_ack_eliciting and space.ack_at is None:
                    # print("setting ack_at")
                    space.ack_at = now + self._ack_delay

    def request_key_update(self) -> None:
        """
        Request an update of the encryption keys.
        """
        assert self._handshake_complete, "cannot change key before handshake completes"
        self._cryptos[tls.Epoch.ONE_RTT].update_key()

    def reset_stream(self, stream_id: int, error_code: int) -> None:
        """
        Abruptly terminate the sending part of a stream.

        :param stream_id: The stream's ID.
        :param error_code: An error code indicating why the stream is being reset.
        """
        stream = self._get_or_create_stream_for_send(stream_id)
        stream.reset(error_code)

    def send_ping(self, uid: int) -> None:
        """
        Send a PING frame to the peer.

        :param uid: A unique ID for this PING.
        """
        self._ping_pending.append(uid)

    def send_datagram_frame(self, data: bytes) -> None:
        """
        Send a DATAGRAM frame.

        :param data: The data to be sent.
        """
        self._datagrams_pending.append(data)

    def send_stream_data(
        self, stream_id: int, data: bytes, end_stream: bool = False
    ) -> None:
        """
        Send data on the specific stream.

        :param stream_id: The stream's ID.
        :param data: The data to be sent.
        :param end_stream: If set to `True`, the FIN bit will be set.
        """
        stream = self._get_or_create_stream_for_send(stream_id)
        stream.write(data, end_stream=end_stream)

    # Private

    def _alpn_handler(self, alpn_protocol: str) -> None:
        """
        Callback which is invoked by the TLS engine when ALPN negotiation completes.
        """
        self._events.append(events.ProtocolNegotiated(alpn_protocol=alpn_protocol))

    def _assert_stream_can_receive(self, frame_type: int, stream_id: int) -> None:
        """
        Check the specified stream can receive data or raises a QuicConnectionError.
        """
        if not self._stream_can_receive(stream_id):
            raise QuicConnectionError(
                error_code=QuicErrorCode.STREAM_STATE_ERROR,
                frame_type=frame_type,
                reason_phrase="Stream is send-only",
            )

    def _assert_stream_can_send(self, frame_type: int, stream_id: int) -> None:
        """
        Check the specified stream can send data or raises a QuicConnectionError.
        """
        if not self._stream_can_send(stream_id):
            raise QuicConnectionError(
                error_code=QuicErrorCode.STREAM_STATE_ERROR,
                frame_type=frame_type,
                reason_phrase="Stream is receive-only",
            )

    def _consume_peer_cid(self, uniflow_id: int) -> None:
        """
        Update the destination connection ID by taking the next
        available connection ID provided by the peer.
        """
        uniflow = self._sending_uniflows[uniflow_id]
        uniflow.cid = uniflow.cid_available.pop(0)
        self._logger.debug(
            "Switching to CID %s (%d)",
            dump_cid(uniflow.cid.cid),
            uniflow.cid.sequence_number,
        )

    def _close_begin(self, is_initiator: bool, now: float) -> None:
        """
        Begin the close procedure.
        """
        timeout = self._sending_uniflows[0].loss.get_probe_timeout()
        for suniflow in self._sending_uniflows.values():
            uniflow_timeout = suniflow.loss.get_probe_timeout()
            if uniflow_timeout < timeout:
                timeout = uniflow_timeout
        self._close_at = now + 3 * timeout
        if is_initiator:
            self._set_state(QuicConnectionState.CLOSING)
        else:
            self._set_state(QuicConnectionState.DRAINING)

    def _close_end(self) -> None:
        """
        End the close procedure.
        """
        self._close_at = None
        for i in range(len(self._receiving_uniflows.values())):
            for epoch in self._receiving_uniflows[i].receiving_spaces.keys():
                self._discard_epoch(epoch)
        self._events.append(self._close_event)
        self._set_state(QuicConnectionState.TERMINATED)

        # signal log end
        if self._quic_logger is not None:
            self._configuration.quic_logger.end_trace(
                self._quic_logger, self._is_client
            )
            self._quic_logger = None

    def _connect(self, now: float) -> None:
        """
        Start the client handshake.
        """
        assert self._is_client

        self._close_at = now + self._configuration.idle_timeout
        self._initialize(self._sending_uniflows[0].cid.cid)

        self.tls.handle_message(b"", self._crypto_buffers)
        self._push_crypto_data()

    def _discard_epoch(self, epoch: tls.Epoch) -> None:
        for runiflow in self._receiving_uniflows.values():
            if not runiflow.receiving_spaces[epoch].discarded:
                self._logger.debug("discarding receiving epoch %s", epoch)
                discard_receiving_space(runiflow.receiving_spaces[epoch])
                runiflow.receiving_spaces[epoch].discarded = True

        for suniflow in self._sending_uniflows.values():
            if not suniflow.sending_spaces[epoch].discarded:
                self._logger.debug("discarding sending epoch %s", epoch)
                suniflow.loss.discard_sending_space(suniflow.sending_spaces[epoch])
                suniflow.sending_spaces[epoch].discarded = True

        self._cryptos[epoch].teardown()

    def _set_initial_address(self, address: EndpointAddress):
        swap_address_id = address.address_id
        swap = self._local_addresses[0]
        address.address_id = 0
        swap.address_id = swap_address_id
        self._local_addresses[0] = address
        self._local_addresses[swap_address_id] = swap

    def _find_address(self, addr: NetworkAddress) -> EndpointAddress:
        # check existing perceived addresses
        for idx, address in enumerate(self._perceived_remote_addresses):
            if address.ip_address == addr[0]:
                if address.port is not None:
                    if address.port == addr[1]:
                        return address
                else:
                    return address

        # new perceived address
        address = EndpointAddress(
            address_id=None,
            ip_version=IPVersion.NONE,
            interface_type=IFType.OTHER,
            ip_address=addr[0],
            port=addr[1],
            sequence_number=0,
        )
        self._logger.debug("Network path %s discovered", addr)
        return address

    def _find_local_address(
        self, local_addr: NetworkAddress
    ) -> Optional[EndpointAddress]:
        # check existing local addresses
        for idx, address in self._local_addresses.items():
            if address.ip_address == local_addr[0]:
                if address.port is not None:
                    if address.port == local_addr[1]:
                        return address
                else:
                    return address
        return None

    def _get_or_create_stream(self, frame_type: int, stream_id: int) -> QuicStream:
        """
        Get or create a stream in response to a received frame.
        """
        stream = self._streams.get(stream_id, None)
        if stream is None:
            # check initiator
            if stream_is_client_initiated(stream_id) == self._is_client:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.STREAM_STATE_ERROR,
                    frame_type=frame_type,
                    reason_phrase="Wrong stream initiator",
                )

            # determine limits
            if stream_is_unidirectional(stream_id):
                max_stream_data_local = self._local_max_stream_data_uni
                max_stream_data_remote = 0
                max_streams = self._local_max_streams_uni
            else:
                max_stream_data_local = self._local_max_stream_data_bidi_remote
                max_stream_data_remote = self._remote_max_stream_data_bidi_local
                max_streams = self._local_max_streams_bidi

            # check max streams
            stream_count = (stream_id // 4) + 1
            if stream_count > max_streams.value:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.STREAM_LIMIT_ERROR,
                    frame_type=frame_type,
                    reason_phrase="Too many streams open",
                )
            elif stream_count > max_streams.used:
                max_streams.used = stream_count

            # create stream
            self._logger.debug("Stream %d created by peer" % stream_id)
            stream = self._streams[stream_id] = QuicStream(
                stream_id=stream_id,
                max_stream_data_local=max_stream_data_local,
                max_stream_data_remote=max_stream_data_remote,
            )
        return stream

    def _get_or_create_stream_for_send(self, stream_id: int) -> QuicStream:
        """
        Get or create a QUIC stream in order to send data to the peer.

        This always occurs as a result of an API call.
        """
        if stream_is_client_initiated(stream_id) != self._is_client:
            if stream_id not in self._streams:
                raise ValueError("Cannot send data on unknown peer-initiated stream")
            if stream_is_unidirectional(stream_id):
                raise ValueError(
                    "Cannot send data on peer-initiated unidirectional stream"
                )

        stream = self._streams.get(stream_id, None)
        if stream is None:
            # determine limits
            if stream_is_unidirectional(stream_id):
                max_stream_data_local = 0
                max_stream_data_remote = self._remote_max_stream_data_uni
                max_streams = self._remote_max_streams_uni
                streams_blocked = self._streams_blocked_uni
            else:
                max_stream_data_local = self._local_max_stream_data_bidi_local
                max_stream_data_remote = self._remote_max_stream_data_bidi_remote
                max_streams = self._remote_max_streams_bidi
                streams_blocked = self._streams_blocked_bidi

            # create stream
            stream = self._streams[stream_id] = QuicStream(
                stream_id=stream_id,
                max_stream_data_local=max_stream_data_local,
                max_stream_data_remote=max_stream_data_remote,
            )

            # mark stream as blocked if needed
            if stream_id // 4 >= max_streams:
                stream.is_blocked = True
                streams_blocked.append(stream)
                self._streams_blocked_pending = True
        return stream

    def _handle_session_ticket(self, session_ticket: tls.SessionTicket) -> None:
        if (
            session_ticket.max_early_data_size is not None
            and session_ticket.max_early_data_size != MAX_EARLY_DATA
        ):
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=QuicFrameType.CRYPTO,
                reason_phrase="Invalid max_early_data value %s"
                % session_ticket.max_early_data_size,
            )
        self._session_ticket_handler(session_ticket)

    def _initialize(self, peer_cid: bytes) -> None:
        # TLS
        self.tls = tls.Context(
            alpn_protocols=self._configuration.alpn_protocols,
            cadata=self._configuration.cadata,
            cafile=self._configuration.cafile,
            capath=self._configuration.capath,
            cipher_suites=self.configuration.cipher_suites,
            is_client=self._is_client,
            logger=self._logger,
            max_early_data=None if self._is_client else MAX_EARLY_DATA,
            server_name=self._configuration.server_name,
            verify_mode=self._configuration.verify_mode,
        )
        self.tls.certificate = self._configuration.certificate
        self.tls.certificate_chain = self._configuration.certificate_chain
        self.tls.certificate_private_key = self._configuration.private_key
        self.tls.handshake_extensions = [
            (
                tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS,
                self._serialize_transport_parameters(),
            )
        ]

        # TLS session resumption
        session_ticket = self._configuration.session_ticket
        if (
            self._is_client
            and session_ticket is not None
            and session_ticket.is_valid
            and session_ticket.server_name == self._configuration.server_name
        ):
            self.tls.session_ticket = self._configuration.session_ticket

            # parse saved QUIC transport parameters - for 0-RTT
            if session_ticket.max_early_data_size == MAX_EARLY_DATA:
                for ext_type, ext_data in session_ticket.other_extensions:
                    if ext_type == tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS:
                        self._parse_transport_parameters(
                            ext_data, from_session_ticket=True
                        )
                        break

        # TLS callbacks
        self.tls.alpn_cb = self._alpn_handler
        if self._session_ticket_fetcher is not None:
            self.tls.get_session_ticket_cb = self._session_ticket_fetcher
        if self._session_ticket_handler is not None:
            self.tls.new_session_ticket_cb = self._handle_session_ticket
        self.tls.update_traffic_key_cb = self._update_traffic_key

        # packet spaces
        def create_crypto_pair(epoch: tls.Epoch) -> CryptoPair:
            epoch_name = ["initial", "0rtt", "handshake", "1rtt"][epoch.value]
            secret_names = [
                "server_%s_secret" % epoch_name,
                "client_%s_secret" % epoch_name,
            ]
            recv_secret_name = secret_names[not self._is_client]
            send_secret_name = secret_names[self._is_client]
            return CryptoPair(
                recv_setup_cb=partial(self._log_key_updated, recv_secret_name),
                recv_teardown_cb=partial(self._log_key_retired, recv_secret_name),
                send_setup_cb=partial(self._log_key_updated, send_secret_name),
                send_teardown_cb=partial(self._log_key_retired, send_secret_name),
            )

        self._cryptos = dict(
            (epoch, create_crypto_pair(epoch))
            for epoch in (
                tls.Epoch.INITIAL,
                tls.Epoch.ZERO_RTT,
                tls.Epoch.HANDSHAKE,
                tls.Epoch.ONE_RTT,
            )
        )
        self._crypto_buffers = {
            tls.Epoch.INITIAL: Buffer(capacity=CRYPTO_BUFFER_SIZE),
            tls.Epoch.HANDSHAKE: Buffer(capacity=CRYPTO_BUFFER_SIZE),
            tls.Epoch.ONE_RTT: Buffer(capacity=CRYPTO_BUFFER_SIZE),
        }
        self._crypto_streams = {
            tls.Epoch.INITIAL: QuicStream(),
            tls.Epoch.HANDSHAKE: QuicStream(),
            tls.Epoch.ONE_RTT: QuicStream(),
        }
        self._receiving_uniflows[0].receiving_spaces = {
            tls.Epoch.INITIAL: QuicReceivingPacketSpace(),
            tls.Epoch.HANDSHAKE: QuicReceivingPacketSpace(),
            tls.Epoch.ONE_RTT: QuicReceivingPacketSpace(),
        }
        self._sending_uniflows[0].sending_spaces = {
            tls.Epoch.INITIAL: QuicSendingPacketSpace(),
            tls.Epoch.HANDSHAKE: QuicSendingPacketSpace(),
            tls.Epoch.ONE_RTT: QuicSendingPacketSpace(),
        }

        self._cryptos[tls.Epoch.INITIAL].setup_initial(
            cid=peer_cid, is_client=self._is_client, version=self._version
        )

        self._sending_uniflows[0].loss.spaces = list(
            self._sending_uniflows[0].sending_spaces.values()
        )

    def _handle_ack_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle an ACK frame.
        """
        # print("handling ACK")
        ack_rangeset, ack_delay_encoded = pull_ack_frame(buf)
        if frame_type == QuicFrameType.ACK_ECN:
            buf.pull_uint_var()
            buf.pull_uint_var()
            buf.pull_uint_var()
        ack_delay = (ack_delay_encoded << self._remote_ack_delay_exponent) / 1000000

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_ack_frame(ack_rangeset, ack_delay)
            )

        suniflow = self._sending_uniflows[0]
        # check whether peer completed address validation
        if not suniflow.loss.peer_completed_address_validation and context.epoch in (
            tls.Epoch.HANDSHAKE,
            tls.Epoch.ONE_RTT,
        ):
            suniflow.loss.peer_completed_address_validation = True

        suniflow.loss.on_ack_received(
            space=suniflow.sending_spaces[context.epoch],
            ack_rangeset=ack_rangeset,
            ack_delay=ack_delay,
            now=context.time,
        )

    def _handle_connection_close_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a CONNECTION_CLOSE frame.
        """
        # print("handling CONNECTION_CLOSE")
        error_code = buf.pull_uint_var()
        if frame_type == QuicFrameType.TRANSPORT_CLOSE:
            frame_type = buf.pull_uint_var()
        else:
            frame_type = None
        reason_length = buf.pull_uint_var()
        try:
            reason_phrase = buf.pull_bytes(reason_length).decode("utf8")
        except UnicodeDecodeError:
            reason_phrase = ""

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_connection_close_frame(
                    error_code=error_code,
                    frame_type=frame_type,
                    reason_phrase=reason_phrase,
                )
            )

        self._logger.info(
            "Connection close code 0x%X, reason %s", error_code, reason_phrase
        )
        self._close_event = events.ConnectionTerminated(
            error_code=error_code, frame_type=frame_type, reason_phrase=reason_phrase
        )
        self._close_begin(is_initiator=False, now=context.time)

    def _handle_crypto_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a CRYPTO frame.
        """
        # print("handling CRYPTO")
        offset = buf.pull_uint_var()
        length = buf.pull_uint_var()
        if offset + length > UINT_VAR_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="offset + length cannot exceed 2^62 - 1",
            )
        frame = QuicStreamFrame(offset=offset, data=buf.pull_bytes(length))

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_crypto_frame(frame)
            )

        stream = self._crypto_streams[context.epoch]
        event = stream.add_frame(frame)
        if event is not None:
            # pass data to TLS layer
            try:
                self.tls.handle_message(event.data, self._crypto_buffers)
                self._push_crypto_data()
            except tls.Alert as exc:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.CRYPTO_ERROR + int(exc.description),
                    frame_type=frame_type,
                    reason_phrase=str(exc),
                )

            # parse transport parameters
            if (
                not self._parameters_received
                and self.tls.received_extensions is not None
            ):
                # print("parse transport params")
                for ext_type, ext_data in self.tls.received_extensions:
                    if ext_type == tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS:
                        self._parse_transport_parameters(ext_data)
                        self._parameters_received = True
                        break
                assert (
                    self._parameters_received
                ), "No QUIC transport parameters received"

            # update current epoch
            if not self._handshake_complete and self.tls.state in [
                tls.State.CLIENT_POST_HANDSHAKE,
                tls.State.SERVER_POST_HANDSHAKE,
            ]:
                self._handshake_complete = True

                # for servers, the handshake is now confirmed
                if not self._is_client:
                    self._discard_epoch(tls.Epoch.HANDSHAKE)
                    self._handshake_confirmed = True
                    self._handshake_done_pending = True

                self._replenish_connection_ids(0)
                self._events.append(
                    events.HandshakeCompleted(
                        alpn_protocol=self.tls.alpn_negotiated,
                        early_data_accepted=self.tls.early_data_accepted,
                        session_resumed=self.tls.session_resumed,
                    )
                )
                self._create_additional_uniflows()
                self._unblock_streams(is_unidirectional=False)
                self._unblock_streams(is_unidirectional=True)
                self._logger.info(
                    "ALPN negotiated protocol %s", self.tls.alpn_negotiated
                )

    def _handle_data_blocked_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a DATA_BLOCKED frame.
        """
        #  print("handling DATA_BLOCKED")
        limit = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_data_blocked_frame(limit=limit)
            )

    def _handle_datagram_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a DATAGRAM frame.
        """
        # print("handling DATAGRAM")
        start = buf.tell()
        if frame_type == QuicFrameType.DATAGRAM_WITH_LENGTH:
            length = buf.pull_uint_var()
        else:
            length = buf.capacity - start
        data = buf.pull_bytes(length)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_datagram_frame(length=length)
            )

        # check frame is allowed
        if (
            self._configuration.max_datagram_frame_size is None
            or buf.tell() - start >= self._configuration.max_datagram_frame_size
        ):
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Unexpected DATAGRAM frame",
            )

        self._events.append(events.DatagramFrameReceived(data=data))

    def _handle_handshake_done_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a HANDSHAKE_DONE frame.
        """
        # print("handling HANDSHAKE_DONE")
        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_handshake_done_frame()
            )

        if not self._is_client:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Clients must not send HANDSHAKE_DONE frames",
            )

        #  for clients, the handshake is now confirmed
        if not self._handshake_confirmed:
            self._discard_epoch(tls.Epoch.HANDSHAKE)
            self._handshake_confirmed = True
            self._sending_uniflows[0].loss.peer_completed_address_validation = True

    def _handle_max_data_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_DATA frame.

        This adjusts the total amount of we can send to the peer.
        """
        # print("handling MAX_DATA")
        max_data = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_connection_limit_frame(
                    frame_type=frame_type, maximum=max_data
                )
            )

        if max_data > self._remote_max_data:
            self._logger.debug("Remote max_data raised to %d", max_data)
            self._remote_max_data = max_data

    def _handle_max_stream_data_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAM_DATA frame.

        This adjusts the amount of data we can send on a specific stream.
        """
        # print("handling MAX_STREAM_DATA")
        stream_id = buf.pull_uint_var()
        max_stream_data = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_max_stream_data_frame(
                    maximum=max_stream_data, stream_id=stream_id
                )
            )

        # check stream direction
        self._assert_stream_can_send(frame_type, stream_id)

        stream = self._get_or_create_stream(frame_type, stream_id)
        if max_stream_data > stream.max_stream_data_remote:
            self._logger.debug(
                "Stream %d remote max_stream_data raised to %d",
                stream_id,
                max_stream_data,
            )
            stream.max_stream_data_remote = max_stream_data

    def _handle_max_streams_bidi_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAMS_BIDI frame.

        This raises number of bidirectional streams we can initiate to the peer.
        """
        # print("handling MAX_STREAMS_BIDI")
        max_streams = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_connection_limit_frame(
                    frame_type=frame_type, maximum=max_streams
                )
            )

        if max_streams > self._remote_max_streams_bidi:
            self._logger.debug("Remote max_streams_bidi raised to %d", max_streams)
            self._remote_max_streams_bidi = max_streams
            self._unblock_streams(is_unidirectional=False)

    def _handle_max_streams_uni_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAMS_UNI frame.

        This raises number of unidirectional streams we can initiate to the peer.
        """
        # print("handling MAX_STREAMS_UNI")
        max_streams = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_connection_limit_frame(
                    frame_type=frame_type, maximum=max_streams
                )
            )

        if max_streams > self._remote_max_streams_uni:
            self._logger.debug("Remote max_streams_uni raised to %d", max_streams)
            self._remote_max_streams_uni = max_streams
            self._unblock_streams(is_unidirectional=True)

    def _handle_new_connection_id_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a NEW_CONNECTION_ID frame.
        """
        # print("handling NEW_CONNECTION_ID")
        sequence_number = buf.pull_uint_var()
        retire_prior_to = buf.pull_uint_var()
        length = buf.pull_uint8()
        connection_id = buf.pull_bytes(length)
        stateless_reset_token = buf.pull_bytes(16)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_new_connection_id_frame(
                    connection_id=connection_id,
                    retire_prior_to=retire_prior_to,
                    sequence_number=sequence_number,
                    stateless_reset_token=stateless_reset_token,
                )
            )

        # sanity check
        if retire_prior_to > sequence_number:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="retire_prior_to is greater than the sequence_number",
            )
        suniflow = self._sending_uniflows[0]
        # determine which CIDs to retire
        change_cid = False
        retire = list(
            filter(
                lambda c: c.sequence_number < retire_prior_to, suniflow.cid_available
            )
        )
        if suniflow.cid.sequence_number < retire_prior_to:
            change_cid = True
            retire.insert(0, suniflow.cid)

        # update available CIDs
        suniflow.cid_available = list(
            filter(
                lambda c: c.sequence_number >= retire_prior_to, suniflow.cid_available
            )
        )
        if sequence_number not in suniflow.cid_sequence_numbers:
            suniflow.cid_available.append(
                QuicConnectionId(
                    cid=connection_id,
                    sequence_number=sequence_number,
                    stateless_reset_token=stateless_reset_token,
                )
            )
            suniflow.cid_sequence_numbers.add(sequence_number)

        # retire previous CIDs
        for quic_connection_id in retire:
            self._retire_peer_cid(0, quic_connection_id)

        # assign new CID if we retired the active one
        if change_cid:
            self._consume_peer_cid(0)

        # check number of active connection IDs, including the selected one
        if 1 + len(suniflow.cid_available) > self._local_active_connection_id_limit:
            raise QuicConnectionError(
                error_code=QuicErrorCode.CONNECTION_ID_LIMIT_ERROR,
                frame_type=frame_type,
                reason_phrase="Too many active connection IDs",
            )

    def _handle_new_token_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a NEW_TOKEN frame.
        """
        # print("handling NEW_TOKEN")
        length = buf.pull_uint_var()
        token = buf.pull_bytes(length)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_new_token_frame(token=token)
            )

        if not self._is_client:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Clients must not send NEW_TOKEN frames",
            )

    def _handle_padding_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PADDING frame.
        """
        # print("handling PADDING")
        # consume padding
        pos = buf.tell()
        for byte in buf.data_slice(pos, buf.capacity):
            if byte:
                break
            pos += 1
        buf.seek(pos)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(self._quic_logger.encode_padding_frame())

    def _handle_path_challenge_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PATH_CHALLENGE frame.
        """
        # print("handling PATH_CHALLENGE")
        data = buf.pull_bytes(8)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_path_challenge_frame(data=data)
            )

        context.receiving_uniflow.remote_challenge = data

    def _handle_path_response_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PATH_RESPONSE frame.
        """
        # print("handling PATH_RESPONSE")
        data = buf.pull_bytes(8)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_path_response_frame(data=data)
            )

        # find the uniflow that sent the challenge
        found_uniflow = None
        for runiflow in self._sending_uniflows.values():
            if not runiflow.path_is_validated and runiflow.local_challenge is not None:
                if runiflow.local_challenge == data:
                    found_uniflow = runiflow
                    break

        if found_uniflow is None:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Response does not match challenge",
            )

        # path is validated
        self._logger.debug(
            "Perceived %s validated by challenge",
            (context.perceived_address.ip_address, context.perceived_address.port),
        )

        found_uniflow.local_challenge = None
        found_uniflow.path_is_validated = True
        found_uniflow.state = UniflowState.ACTIVE
        # print("uniflow", found_uniflow.uniflow_id, "path validated")
        if not self._uniflows_pending:
            self._uniflows_seq += 1
            self._uniflows_pending = True

    def _handle_ping_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PING frame.
        """
        # print("handling PING")
        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(self._quic_logger.encode_ping_frame())

    def _handle_reset_stream_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a RESET_STREAM frame.
        """
        # print("handling RESET_STREAM")
        stream_id = buf.pull_uint_var()
        error_code = buf.pull_uint_var()
        final_size = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_reset_stream_frame(
                    error_code=error_code, final_size=final_size, stream_id=stream_id
                )
            )

        # check stream direction
        self._assert_stream_can_receive(frame_type, stream_id)

        # check flow-control limits
        stream = self._get_or_create_stream(frame_type, stream_id)
        if final_size > stream.max_stream_data_local:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over stream data limit",
            )
        newly_received = max(0, final_size - stream._recv_highest)
        if self._local_max_data.used + newly_received > self._local_max_data.value:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over connection data limit",
            )

        # process reset
        self._logger.info(
            "Stream %d reset by peer (error code %d, final size %d)",
            stream_id,
            error_code,
            final_size,
        )
        try:
            event = stream.handle_reset(error_code=error_code, final_size=final_size)
        except FinalSizeError as exc:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FINAL_SIZE_ERROR,
                frame_type=frame_type,
                reason_phrase=str(exc),
            )
        if event is not None:
            self._events.append(event)
        self._local_max_data.used += newly_received

    def _handle_retire_connection_id_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a RETIRE_CONNECTION_ID frame.
        """
        # print("handling RETIRE_CONNECTION_ID")
        sequence_number = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_retire_connection_id_frame(sequence_number)
            )

        if sequence_number >= self._receiving_uniflows[0].cid_seq:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Cannot retire unknown connection ID",
            )

        # find the connection ID by sequence number
        runiflow = self._receiving_uniflows[0]
        for index, connection_id in enumerate(runiflow.cid_available):
            if connection_id.sequence_number == sequence_number:
                if connection_id.cid == context.host_cid:
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                        frame_type=frame_type,
                        reason_phrase="Cannot retire current connection ID",
                    )
                self._logger.debug(
                    "Peer retiring CID %s (%d)",
                    dump_cid(connection_id.cid),
                    connection_id.sequence_number,
                )
                del self._receiving_uniflows[0].cid_available[index]
                self._events.append(
                    events.ConnectionIdRetired(connection_id=connection_id.cid)
                )
                break

        # issue a new connection ID
        self._replenish_connection_ids(0)

    def _handle_stop_sending_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STOP_SENDING frame.
        """
        # print("handling STOP_SENDING")
        stream_id = buf.pull_uint_var()
        error_code = buf.pull_uint_var()  # application error code

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_stop_sending_frame(
                    error_code=error_code, stream_id=stream_id
                )
            )

        # check stream direction
        self._assert_stream_can_send(frame_type, stream_id)

        self._get_or_create_stream(frame_type, stream_id)

    def _handle_stream_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAM frame.
        """
        # print("handling STREAM")
        stream_id = buf.pull_uint_var()
        if frame_type & 4:
            offset = buf.pull_uint_var()
        else:
            offset = 0
        if frame_type & 2:
            length = buf.pull_uint_var()
        else:
            length = buf.capacity - buf.tell()
        if offset + length > UINT_VAR_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="offset + length cannot exceed 2^62 - 1",
            )
        frame = QuicStreamFrame(
            offset=offset, data=buf.pull_bytes(length), fin=bool(frame_type & 1)
        )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_stream_frame(frame, stream_id=stream_id)
            )

        # check stream direction
        self._assert_stream_can_receive(frame_type, stream_id)

        # check flow-control limits
        stream = self._get_or_create_stream(frame_type, stream_id)
        if offset + length > stream.max_stream_data_local:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over stream data limit",
            )
        newly_received = max(0, offset + length - stream._recv_highest)
        if self._local_max_data.used + newly_received > self._local_max_data.value:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over connection data limit",
            )

        # process data
        try:
            event = stream.add_frame(frame)
        except FinalSizeError as exc:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FINAL_SIZE_ERROR,
                frame_type=frame_type,
                reason_phrase=str(exc),
            )
        if event is not None:
            self._events.append(event)
        self._local_max_data.used += newly_received

    def _handle_stream_data_blocked_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAM_DATA_BLOCKED frame.
        """
        # print("handling STREAM_DATA_BLOCKED")
        stream_id = buf.pull_uint_var()
        limit = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_stream_data_blocked_frame(
                    limit=limit, stream_id=stream_id
                )
            )

        # check stream direction
        self._assert_stream_can_receive(frame_type, stream_id)

        self._get_or_create_stream(frame_type, stream_id)

    def _handle_streams_blocked_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAMS_BLOCKED frame.
        """
        # print("handling STREAMS_BLOCKED")
        limit = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_streams_blocked_frame(
                    is_unidirectional=frame_type == QuicFrameType.STREAMS_BLOCKED_UNI,
                    limit=limit,
                )
            )

    def _handle_mp_new_connection_id_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle an MP_NEW_CONNECTION_ID frame.
        """
        # print("handling MP_NEW_CONNECTION_ID")
        if not self._peer_mp_support:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Multipath frames are not allowed, "
                + "use max_sending_uniflow_id to signal Multipath support",
            )

        uniflow_id = buf.pull_uint_var()
        sequence_number = buf.pull_uint_var()
        retire_prior_to = buf.pull_uint_var()
        length = buf.pull_uint8()
        connection_id = buf.pull_bytes(length)
        stateless_reset_token = buf.pull_bytes(16)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_mp_new_connection_id_frame(
                    connection_id=connection_id,
                    uniflow_id=uniflow_id,
                    retire_prior_to=retire_prior_to,
                    sequence_number=sequence_number,
                    stateless_reset_token=stateless_reset_token,
                )
            )

        # sanity checks
        if retire_prior_to > sequence_number:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Uniflow "
                + str(uniflow_id)
                + " retire_prior_to is greater than the sequence_number",
            )

        if uniflow_id not in self._sending_uniflows.keys():
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Uniflow " + str(uniflow_id) + " does not exist",
            )

        if uniflow_id == 0:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Uniflow "
                + str(uniflow_id)
                + " id not allowed for this frame type",
            )

        suniflow = self._sending_uniflows[uniflow_id]
        # determine which CIDs to retire
        change_cid = False
        change_cid_initial = False
        retire = list(
            filter(
                lambda c: c.sequence_number < retire_prior_to, suniflow.cid_available
            )
        )
        # Check if the uniflow has a valid initial CID
        if suniflow.cid.sequence_number is None:
            change_cid_initial = True
        elif suniflow.cid.sequence_number < retire_prior_to:
            change_cid = True
            retire.insert(0, suniflow.cid)

        # update available CIDs
        suniflow.cid_available = list(
            filter(
                lambda c: c.sequence_number >= retire_prior_to, suniflow.cid_available
            )
        )
        if sequence_number not in suniflow.cid_sequence_numbers:
            suniflow.cid_available.append(
                QuicConnectionId(
                    cid=connection_id,
                    sequence_number=sequence_number,
                    stateless_reset_token=stateless_reset_token,
                )
            )
            suniflow.cid_sequence_numbers.add(sequence_number)

        if change_cid_initial:
            suniflow.cid = suniflow.cid_available.pop(0)

        # retire previous CIDs
        for quic_connection_id in retire:
            self._retire_peer_cid(uniflow_id, quic_connection_id)

        # assign new CID if we retired the active one
        if change_cid:
            self._consume_peer_cid(uniflow_id)

        # check number of active connection IDs, including the selected one
        if 1 + len(suniflow.cid_available) > self._local_active_connection_id_limit:
            raise QuicConnectionError(
                error_code=QuicErrorCode.CONNECTION_ID_LIMIT_ERROR,
                frame_type=frame_type,
                reason_phrase="Uniflow "
                + str(uniflow_id)
                + " too many active connection IDs",
            )

    def _handle_mp_retire_connection_id_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle an MP_RETIRE_CONNECTION_ID frame.
        """
        # print("handling MP_RETIRE_CONNECTION_ID")
        if not self._peer_mp_support:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Multipath frames are not allowed, "
                + "use max_sending_uniflow_id to signal Multipath support",
            )

        uniflow_id = buf.pull_uint_var()
        sequence_number = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_mp_retire_connection_id_frame(
                    uniflow_id, sequence_number
                )
            )

        if uniflow_id not in self._receiving_uniflows.keys():
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Uniflow " + str(uniflow_id) + " does not exist",
            )

        if uniflow_id == 0:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Uniflow "
                + str(uniflow_id)
                + " id not allowed for this frame type",
            )

        if sequence_number >= self._receiving_uniflows[uniflow_id].cid_seq:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Uniflow "
                + str(uniflow_id)
                + " cannot retire unknown connection ID",
            )

        # find the connection ID by sequence number
        runiflow = self._receiving_uniflows[uniflow_id]
        for index, connection_id in enumerate(runiflow.cid_available):
            if connection_id.sequence_number == sequence_number:
                if connection_id.cid == context.host_cid:
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                        frame_type=frame_type,
                        reason_phrase="Uniflow "
                        + str(uniflow_id)
                        + " cannot retire current connection ID",
                    )
                self._logger.debug(
                    "Peer retiring CID %s (%d)",
                    dump_cid(connection_id.cid),
                    connection_id.sequence_number,
                )
                del self._receiving_uniflows[uniflow_id].cid_available[index]
                self._events.append(
                    events.MPConnectionIdRetired(
                        connection_id=connection_id.cid, uniflow_id=uniflow_id
                    )
                )
                break

        # issue a new connection ID
        self._replenish_connection_ids(uniflow_id)

    def _handle_mp_ack_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle an MP_ACK frame.
        """
        # print("handling MP_ACK")
        if not self._peer_mp_support:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Multipath frames are not allowed, "
                + "use max_sending_uniflow_id to signal Multipath support",
            )

        uniflow_id = buf.pull_uint_var()
        ack_rangeset, ack_delay_encoded = pull_ack_frame(buf)
        if frame_type == QuicFrameType.ACK_ECN:
            buf.pull_uint_var()
            buf.pull_uint_var()
            buf.pull_uint_var()
        ack_delay = (ack_delay_encoded << self._remote_ack_delay_exponent) / 1000000

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_mp_ack_frame(
                    uniflow_id, ack_rangeset, ack_delay
                )
            )

        # sanity checks
        if uniflow_id not in self._sending_uniflows.keys():
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Uniflow " + str(uniflow_id) + " does not exist",
            )

        # Patch for PQUIC  # Disable for pquic connection
        # if uniflow_id == 0:
        #    raise QuicConnectionError(
        #        error_code=QuicErrorCode.PROTOCOL_VIOLATION,
        #        frame_type=frame_type,
        #        reason_phrase="Uniflow "
        #        + str(uniflow_id)
        #        + " id not allowed for this frame type",
        #    )

        suniflow = self._sending_uniflows[uniflow_id]
        # todo: don't check for peer completed address validation --> path response should do this
        # check whether peer completed address validation
        # if not suniflow.loss.peer_completed_address_validation and context.epoch in (
        #         tls.Epoch.HANDSHAKE,
        #         tls.Epoch.ONE_RTT,
        # ):
        #     suniflow.loss.peer_completed_address_validation = True

        suniflow.loss.on_ack_received(
            space=suniflow.sending_spaces[context.epoch],
            ack_rangeset=ack_rangeset,
            ack_delay=ack_delay,
            now=context.time,
        )
        self._MP = True  # Patch for pquic connection

    def _handle_add_address_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle an ADD_ADDRESS frame
        """
        # print("handling ADD_ADDRESS")
        if not self._peer_mp_support:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Multipath frames are not allowed, "
                + "use max_sending_uniflow_id to signal Multipath support",
            )

        first_byte = buf.pull_uint8()
        ip_version = IPVersion(first_byte & 15)
        address_id = buf.pull_uint8()
        sequence_number = buf.pull_uint_var()
        ift = buf.pull_uint8()
        interface_type = IFType(ift)
        version, length = (
            (socket.AF_INET, 4)
            if ip_version == IPVersion.IPV4
            else (socket.AF_INET6, 16)
        )
        ip_bytes = buf.pull_bytes(length)
        ip_address = socket.inet_ntop(version, ip_bytes)
        port = (
            buf.pull_uint16()
            if first_byte & 16
            else context.receiving_uniflow.source_address.port
            # based on MPTCP spec
        )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_add_address_frame(
                    address_id=address_id,
                    sequence_number=sequence_number,
                    interface_type=interface_type,
                    ip_version=ip_version,
                    ip_address=ip_address,
                    port=port,
                )
            )
        # check if we already have a communicated address with the same address_id
        if address_id in self._remote_addresses.keys():
            address = self._remote_addresses[address_id]
            # check the sequence number
            if sequence_number > address.sequence_number:
                address.ip_version = ip_version
                address.interface_type = interface_type
                address.ip_address = ip_address
                address.port = port
                address.sequence_number = sequence_number
                address.is_enabled = True
        else:
            # check if we already have a perceived address with the same ip and port
            address = None
            for i in range(len(self._perceived_remote_addresses)):
                addr = self._perceived_remote_addresses[i]
                if ip_address == addr.ip_address and port == addr.port:
                    address = addr

            if address:
                # update address info
                address.address_id = address_id
                address.ip_version = ip_version
                address.interface_type = interface_type
                address.sequence_number = sequence_number
                address.is_enabled = True

                self._remote_addresses[address_id] = address
            else:
                # add address
                new_address = EndpointAddress(
                    address_id=address_id,
                    ip_version=ip_version,
                    interface_type=interface_type,
                    ip_address=ip_address,
                    port=port,
                    sequence_number=sequence_number,
                )
                self._remote_addresses[address_id] = new_address
                self._perceived_remote_addresses.append(new_address)

    def _handle_remove_address_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a REMOVE_ADDRESS frame
        """
        # print("handling REMOVE_ADDRESS")
        if not self._peer_mp_support:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Multipath frames are not allowed, "
                + "use max_sending_uniflow_id to signal Multipath support",
            )

        address_id = buf.pull_uint8()
        sequence_number = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_remove_address_frame(
                    address_id, sequence_number
                )
            )

        if address_id in self._remote_addresses.keys():
            address = self._remote_addresses[address_id]
            # check the sequence number
            if sequence_number > address.sequence_number:
                self._remote_addresses[address_id].sequence_number = sequence_number
                self._remote_addresses[address_id].is_enabled = False
                # reset all the uniflows using this address
                for uniflow in self._sending_uniflows.values():
                    if uniflow.destination_address is address:
                        uniflow.reset()

    def _handle_uniflows_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        # print("handling UNIFLOWS")
        """
        Handle a UNIFlOWS_ADDRESS frame
        """
        if not self._peer_mp_support:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Multipath frames are not allowed, "
                + "use max_sending_uniflow_id to signal Multipath support",
            )

        sequence_number = buf.pull_uint_var()
        rcvUni = buf.pull_uint_var()
        sndUni = buf.pull_uint_var()
        receiving_uniflows = []
        active_sending_uniflows = []
        for _ in range(rcvUni):
            uniflow_id = buf.pull_uint_var()
            local_address_id = buf.pull_uint8()
            receiving_uniflows.append(
                {"uniflow_id": uniflow_id, "local_address_id": local_address_id}
            )
        for _ in range(sndUni):
            uniflow_id = buf.pull_uint_var()
            local_address_id = buf.pull_uint8()
            active_sending_uniflows.append(
                {"uniflow_id": uniflow_id, "local_address_id": local_address_id}
            )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_uniflows_frame(
                    sequence_number=sequence_number,
                    receiving_uniflows=receiving_uniflows,
                    active_sending_uniflows=active_sending_uniflows,
                )
            )

        if sequence_number > self._remote_uniflows_seq:
            self._remote_uniflows_seq = sequence_number
            for asuniflow in active_sending_uniflows:
                uniflow_id = asuniflow["uniflow_id"]
                local_address_id = asuniflow["local_address_id"]

                # sanity check
                if (
                    uniflow_id not in self._receiving_uniflows.keys()
                    or local_address_id not in self._remote_addresses.keys()
                ):
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                        frame_type=frame_type,
                        reason_phrase="Multipath frame contains invalid ids",
                    )

                specified_uniflow = self._receiving_uniflows[uniflow_id]
                perceived_address = specified_uniflow.source_address
                specified_address = self._remote_addresses[local_address_id]

                # 4 possibilities: receiving uniflow source address
                # 1: is None, 2: address_id is None, 3: address_id is same value, 4: address_id is other value
                if perceived_address is None:
                    # receiving uniflow doesn't have a source address yet
                    specified_uniflow.source_address = specified_address
                    specified_uniflow.perceived_remote_addresses.append(
                        specified_address
                    )
                elif perceived_address.address_id is None:
                    # link the perceived address to the communicated address
                    specified_address.ip_address = perceived_address.ip_address
                    specified_address.port = perceived_address.port
                    specified_uniflow.source_address = specified_address
                    for i in range(len(specified_uniflow.perceived_remote_addresses)):
                        if (
                            specified_uniflow.perceived_remote_addresses[i]
                            is perceived_address
                        ):
                            su_pra = specified_uniflow.perceived_remote_addresses
                            su_pra[i] = specified_address

                    # update all other receiving uniflows that use this address
                    for runiflow in self._receiving_uniflows.values():
                        if runiflow.source_address is perceived_address:
                            runiflow.source_address = specified_address
                        for i in range(len(runiflow.perceived_remote_addresses)):
                            if (
                                runiflow.perceived_remote_addresses[i]
                                is perceived_address
                            ):
                                ru_pra = runiflow.perceived_remote_addresses
                                ru_pra[i] = specified_address

                    # sending uniflow destination addresses are based on the remote addresses
                    # thus, the address is updated automatically

                    self._perceived_remote_addresses.remove(perceived_address)
                    # todo: retry path validation after the address update?
                elif perceived_address.address_id == local_address_id:
                    # same address
                    pass
                else:
                    # not same address
                    specified_uniflow.source_address = specified_address
                    if (
                        specified_address
                        not in specified_uniflow.perceived_remote_addresses
                    ):
                        specified_uniflow.perceived_remote_addresses.insert(
                            0, specified_address
                        )

    def _log_key_retired(self, key_type: str, trigger: str) -> None:
        """
        Log a key retirement.
        """
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="security",
                event="key_retired",
                data={"key_type": key_type, "trigger": trigger},
            )

    def _log_key_updated(self, key_type: str, trigger: str) -> None:
        """
        Log a key update.
        """
        # print("key updated")
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="security",
                event="key_updated",
                data={"key_type": key_type, "trigger": trigger},
            )

    def _on_ack_delivery(
        self,
        delivery: QuicDeliveryState,
        space: QuicReceivingPacketSpace,
        highest_acked: int,
    ) -> None:
        """
        Callback when an ACK frame is acknowledged or lost.
        """
        if delivery == QuicDeliveryState.ACKED:
            space.ack_queue.subtract(0, highest_acked + 1)

    def _on_connection_limit_delivery(
        self, delivery: QuicDeliveryState, limit: Limit
    ) -> None:
        """
        Callback when a MAX_DATA or MAX_STREAMS frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            limit.sent = 0

    def _on_handshake_done_delivery(self, delivery: QuicDeliveryState) -> None:
        """
        Callback when a HANDSHAKE_DONE frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            self._handshake_done_pending = True

    def _on_max_stream_data_delivery(
        self, delivery: QuicDeliveryState, stream: QuicStream
    ) -> None:
        """
        Callback when a MAX_STREAM_DATA frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            stream.max_stream_data_local_sent = 0

    def _on_new_connection_id_delivery(
        self, delivery: QuicDeliveryState, connection_id: QuicConnectionId
    ) -> None:
        """
        Callback when a NEW_CONNECTION_ID frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            connection_id.was_sent = False

    def _on_path_challenge_delivery(
        self, delivery: QuicDeliveryState, challenge: bytes, uniflow_id: int
    ):
        if delivery != QuicDeliveryState.ACKED:
            suniflow = self._sending_uniflows[uniflow_id]
            if suniflow.local_challenge == challenge:
                suniflow.reset()
                self.change_connection_id(suniflow.uniflow_id)

    def _on_ping_delivery(
        self, delivery: QuicDeliveryState, uids: Sequence[int]
    ) -> None:
        """
        Callback when a PING frame is acknowledged or lost.
        """
        if delivery == QuicDeliveryState.ACKED:
            self._logger.debug("Received PING%s response", "" if uids else " (probe)")
            for uid in uids:
                self._events.append(events.PingAcknowledged(uid=uid))
        else:
            self._ping_pending.extend(uids)

    def _on_retire_connection_id_delivery(
        self, delivery: QuicDeliveryState, sequence_number: int
    ) -> None:
        """
        Callback when a RETIRE_CONNECTION_ID frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            self._sending_uniflows[0].retire_connection_ids.append(sequence_number)

    def _on_mp_new_connection_id_delivery(
        self,
        delivery: QuicDeliveryState,
        connection_id: QuicConnectionId,
        uniflow_id: int,
    ) -> None:
        """
        Callback when a MP_NEW_CONNECTION_ID frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            connection_id.was_sent = False

    def _on_mp_retire_connection_id_delivery(
        self, delivery: QuicDeliveryState, sequence_number: int, uniflow_id: int
    ) -> None:
        """
        Callback when a MP_RETIRE_CONNECTION_ID frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            self._sending_uniflows[uniflow_id].retire_connection_ids.append(
                sequence_number
            )

    def _on_mp_ack_delivery(
        self,
        delivery: QuicDeliveryState,
        space: QuicReceivingPacketSpace,
        highest_acked: int,
    ) -> None:
        """
        Callback when an MP_ACK frame is acknowledged or lost.
        """
        if delivery == QuicDeliveryState.ACKED:
            space.ack_queue.subtract(0, highest_acked + 1)

    def _on_add_address_delivery(
        self, delivery: QuicDeliveryState, address_id: int
    ) -> None:
        """
        Callback when a ADD_ADDRESS frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            self._local_addresses[address_id].was_sent = False

    def _on_remove_address_delivery(
        self, delivery: QuicDeliveryState, address_id: int
    ) -> None:
        """
        Callback when a REMOVE_ADDRESS frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            self._removed_addresses.append(address_id)

    def _on_uniflows_delivery(self, delivery: QuicDeliveryState) -> None:
        """
        Callback when a Uniflows frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            self._uniflows_pending = True

    def _payload_received(
        self, context: QuicReceiveContext, plain: bytes
    ) -> Tuple[bool, bool]:
        """
        Handle a QUIC packet payload.
        """
        buf = Buffer(data=plain)

        is_ack_eliciting = False
        is_probing = None
        while not buf.eof():
            frame_type = buf.pull_uint_var()

            # check frame type is known
            try:
                frame_handler, frame_epochs = self.__frame_handlers[frame_type]
            except KeyError:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=frame_type,
                    reason_phrase="Unknown frame type",
                )

            # check frame is allowed for the epoch
            if context.epoch not in frame_epochs:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=frame_type,
                    reason_phrase="Unexpected frame type",
                )

            # handle the frame
            try:
                frame_handler(context, frame_type, buf)
            except BufferReadError:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                    frame_type=frame_type,
                    reason_phrase="Failed to parse frame",
                )

            # update ACK only / probing flags
            if frame_type not in NON_ACK_ELICITING_FRAME_TYPES:
                is_ack_eliciting = True

            if frame_type not in PROBING_FRAME_TYPES:
                is_probing = False
            elif is_probing is None:
                is_probing = True

        return is_ack_eliciting, bool(is_probing)

    def _replenish_connection_ids(self, uniflow_id: int) -> None:
        """
        Generate new connection IDs.
        """
        uniflow = self._receiving_uniflows[uniflow_id]
        while len(uniflow.cid_available) < min(
            8, self._remote_active_connection_id_limit
        ):
            uniflow.cid_available.append(
                QuicConnectionId(
                    cid=os.urandom(self._configuration.connection_id_length),
                    sequence_number=uniflow.cid_seq,
                    stateless_reset_token=os.urandom(16),
                )
            )
            uniflow.cid_seq += 1

    def _retire_peer_cid(
        self, uniflow_id: int, connection_id: QuicConnectionId
    ) -> None:
        """
        Retire a destination connection ID.
        """
        self._logger.debug(
            "Retiring CID %s (%d)",
            dump_cid(connection_id.cid),
            connection_id.sequence_number,
        )
        self._sending_uniflows[uniflow_id].retire_connection_ids.append(
            connection_id.sequence_number,
        )

    def _push_crypto_data(self) -> None:
        for epoch, buf in self._crypto_buffers.items():
            self._crypto_streams[epoch].write(buf.data)
            buf.seek(0)

    def _parse_transport_parameters(
        self, data: bytes, from_session_ticket: bool = False
    ) -> None:
        """
        Parse and apply remote transport parameters.

        `from_session_ticket` is `True` when restoring saved transport parameters,
        and `False` when handling received transport parameters.
        """

        quic_transport_parameters = pull_quic_transport_parameters(Buffer(data=data))

        # log event
        if self._quic_logger is not None and not from_session_ticket:
            self._quic_logger.log_event(
                category="transport",
                event="parameters_set",
                data=self._quic_logger.encode_transport_parameters(
                    owner="remote", parameters=quic_transport_parameters
                ),
            )

        # validate remote parameters
        if not self._is_client:
            for attr in [
                "original_destination_connection_id",
                "preferred_address",
                "retry_source_connection_id",
                "stateless_reset_token",
            ]:
                if getattr(quic_transport_parameters, attr) is not None:
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                        frame_type=QuicFrameType.CRYPTO,
                        reason_phrase="%s is not allowed for clients" % attr,
                    )

        if not from_session_ticket:
            if self._is_client and (
                quic_transport_parameters.original_destination_connection_id
                != self._original_destination_connection_id
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="original_destination_connection_id does not match",
                )
            if self._is_client and (
                quic_transport_parameters.retry_source_connection_id
                != self._retry_source_connection_id
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="retry_source_connection_id does not match",
                )
            if (
                quic_transport_parameters.active_connection_id_limit is not None
                and quic_transport_parameters.active_connection_id_limit < 2
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="active_connection_id_limit must be no less than 2",
                )
            suniflow = self._sending_uniflows[0]
            if (
                self._is_client
                and suniflow.cid.sequence_number == 0
                and quic_transport_parameters.stateless_reset_token is not None
            ):
                suniflow.cid.stateless_reset_token = (
                    quic_transport_parameters.stateless_reset_token
                )

        # store remote parameters
        if not from_session_ticket:
            if quic_transport_parameters.ack_delay_exponent is not None:
                self._remote_ack_delay_exponent = self._remote_ack_delay_exponent
            if quic_transport_parameters.max_ack_delay is not None:
                # fixme: set this for all uniflows
                self._sending_uniflows[0].loss.max_ack_delay = (
                    quic_transport_parameters.max_ack_delay / 1000.0
                )
        if quic_transport_parameters.active_connection_id_limit is not None:
            self._remote_active_connection_id_limit = (
                quic_transport_parameters.active_connection_id_limit
            )
        if quic_transport_parameters.max_idle_timeout is not None:
            self._remote_max_idle_timeout = (
                quic_transport_parameters.max_idle_timeout / 1000.0
            )
        self._remote_max_datagram_frame_size = (
            quic_transport_parameters.max_datagram_frame_size
        )
        for param in [
            "max_data",
            "max_stream_data_bidi_local",
            "max_stream_data_bidi_remote",
            "max_stream_data_uni",
            "max_streams_bidi",
            "max_streams_uni",
        ]:
            value = getattr(quic_transport_parameters, "initial_" + param)
            if value is not None:
                setattr(self, "_remote_" + param, value)
        if quic_transport_parameters.max_sending_uniflow_id is not None:
            self._peer_mp_support = True
            self._peer_max_sending_uniflows_id = (
                quic_transport_parameters.max_sending_uniflow_id
            )

    def _serialize_transport_parameters(self) -> bytes:
        runiflow = self._receiving_uniflows[0]
        quic_transport_parameters = QuicTransportParameters(
            ack_delay_exponent=self._local_ack_delay_exponent,
            active_connection_id_limit=self._local_active_connection_id_limit,
            max_idle_timeout=int(self._configuration.idle_timeout * 1000),
            initial_max_data=self._local_max_data.value,
            initial_max_stream_data_bidi_local=self._local_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote=self._local_max_stream_data_bidi_remote,
            initial_max_stream_data_uni=self._local_max_stream_data_uni,
            initial_max_streams_bidi=self._local_max_streams_bidi.value,
            initial_max_streams_uni=self._local_max_streams_uni.value,
            initial_source_connection_id=self._local_initial_source_connection_id,
            max_ack_delay=25,
            max_datagram_frame_size=self._configuration.max_datagram_frame_size,
            max_sending_uniflow_id=self._configuration.max_sending_uniflow_id,
            quantum_readiness=b"Q" * 1200
            if self._configuration.quantum_readiness_test
            else None,
            stateless_reset_token=runiflow.cid_available[0].stateless_reset_token,
            max_udp_payload_size=1440,
        )
        if not self._is_client and (
            self._version >= QuicProtocolVersion.DRAFT_28
            or self._retry_source_connection_id
        ):
            quic_transport_parameters.original_destination_connection_id = (
                self._original_destination_connection_id
            )
            quic_transport_parameters.retry_source_connection_id = (
                self._retry_source_connection_id
            )

        # log event
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="transport",
                event="parameters_set",
                data=self._quic_logger.encode_transport_parameters(
                    owner="local", parameters=quic_transport_parameters
                ),
            )

        buf = Buffer(capacity=3 * PACKET_MAX_SIZE)
        push_quic_transport_parameters(buf, quic_transport_parameters)
        return buf.data

    def _set_state(self, state: QuicConnectionState) -> None:
        self._logger.debug("%s -> %s", self._state, state)
        self._state = state

    def _stream_can_receive(self, stream_id: int) -> bool:
        return stream_is_client_initiated(
            stream_id
        ) != self._is_client or not stream_is_unidirectional(stream_id)

    def _stream_can_send(self, stream_id: int) -> bool:
        return stream_is_client_initiated(
            stream_id
        ) == self._is_client or not stream_is_unidirectional(stream_id)

    def _unblock_streams(self, is_unidirectional: bool) -> None:
        if is_unidirectional:
            max_stream_data_remote = self._remote_max_stream_data_uni
            max_streams = self._remote_max_streams_uni
            streams_blocked = self._streams_blocked_uni
        else:
            max_stream_data_remote = self._remote_max_stream_data_bidi_remote
            max_streams = self._remote_max_streams_bidi
            streams_blocked = self._streams_blocked_bidi

        while streams_blocked and streams_blocked[0].stream_id // 4 < max_streams:
            stream = streams_blocked.pop(0)
            stream.is_blocked = False
            stream.max_stream_data_remote = max_stream_data_remote

        if not self._streams_blocked_bidi and not self._streams_blocked_uni:
            self._streams_blocked_pending = False

    def _update_traffic_key(
        self,
        direction: tls.Direction,
        epoch: tls.Epoch,
        cipher_suite: tls.CipherSuite,
        secret: bytes,
    ) -> None:
        """
        Callback which is invoked by the TLS engine when new traffic keys are
        available.
        """
        secrets_log_file = self._configuration.secrets_log_file
        if secrets_log_file is not None:
            label_row = self._is_client == (direction == tls.Direction.DECRYPT)
            label = SECRETS_LABELS[label_row][epoch.value]
            secrets_log_file.write(
                "%s %s %s\n" % (label, self.tls.client_random.hex(), secret.hex())
            )
            secrets_log_file.flush()

        crypto = self._cryptos[epoch]
        if direction == tls.Direction.ENCRYPT:
            crypto.send.setup(
                cipher_suite=cipher_suite, secret=secret, version=self._version
            )
        else:
            crypto.recv.setup(
                cipher_suite=cipher_suite, secret=secret, version=self._version
            )

    def _create_additional_uniflows(self) -> None:
        if self._peer_mp_support:
            for i in range(1, self._peer_max_sending_uniflows_id + 1):
                self._receiving_uniflows[i] = QuicReceivingUniflow(
                    uniflow_id=i,
                    is_first=False,
                    configuration=self.configuration,
                )
                self._receiving_uniflows[i].receiving_spaces = {
                    tls.Epoch.INITIAL: QuicReceivingPacketSpace(),
                    tls.Epoch.HANDSHAKE: QuicReceivingPacketSpace(),
                    tls.Epoch.ONE_RTT: QuicReceivingPacketSpace(),
                }
                self._replenish_connection_ids(i)
            for i in range(1, int(self._max_sending_uniflows_id or 0) + 1):
                self._sending_uniflows[i] = QuicSendingUniflow(
                    uniflow_id=i,
                    is_first=False,
                    configuration=self.configuration,
                    congestion_windows_all=self._congestion_windows_all,
                    quic_logger=self._quic_logger,
                )
                self._sending_uniflows[i].sending_spaces = {
                    tls.Epoch.INITIAL: QuicSendingPacketSpace(),
                    tls.Epoch.HANDSHAKE: QuicSendingPacketSpace(),
                    tls.Epoch.ONE_RTT: QuicSendingPacketSpace(),
                }
                self._sending_uniflows[i].loss.spaces = list(
                    self._sending_uniflows[i].sending_spaces.values()
                )

    def _write_application(
        self,
        builders: Dict[int, Tuple[QuicSendingUniflow, QuicPacketBuilder]],
        now: float,
    ) -> Dict[int, Tuple[QuicSendingUniflow, QuicPacketBuilder]]:
        crypto_stream: Optional[QuicStream] = None
        if self._cryptos[tls.Epoch.ONE_RTT].send.is_valid():
            crypto = self._cryptos[tls.Epoch.ONE_RTT]
            crypto_stream = self._crypto_streams[tls.Epoch.ONE_RTT]
            packet_type = PACKET_TYPE_ONE_RTT
        elif self._cryptos[tls.Epoch.ZERO_RTT].send.is_valid():
            crypto = self._cryptos[tls.Epoch.ZERO_RTT]
            packet_type = PACKET_TYPE_ZERO_RTT
        else:
            return builders

        self._builder_manager.start_manager(builders)
        iruniflow = self._receiving_uniflows[0]

        # print("active builders:", self._builder_manager.length_active_builders())

        while self._builder_manager.length_active_builders() > 0:
            # print("new loop")
            paced_uniflows: List[int] = []
            # fixme: apply a method to select the ack-sending uniflow(s)
            chosen_ack_uniflow_id = list(self._builder_manager.builders.keys())[0]
            ack_item = self._builder_manager.builders[chosen_ack_uniflow_id]
            # chosen_ack_uniflow = ack_item[0]
            chosen_ack_builder = ack_item[1]

            # apply pacing for each uniflow, except for the ack-sending uniflow if we have acks to send
            for item in self._builder_manager.builders.items():
                uniflow_id = item[0]
                auniflow = item[1][0]
                # builder = item[1][1]
                apply_pacing = True
                if uniflow_id == chosen_ack_uniflow_id:
                    for runiflow in self._receiving_uniflows.values():
                        space = runiflow.receiving_spaces[tls.Epoch.ONE_RTT]
                        if space.ack_at is not None and space.ack_at <= now:
                            apply_pacing = False

                if apply_pacing:
                    auniflow.pacing_at = auniflow.loss._pacer.next_send_time(now=now)
                    if auniflow.pacing_at is not None:
                        paced_uniflows.append(uniflow_id)
                        if uniflow_id == chosen_ack_uniflow_id:
                            chosen_ack_uniflow_id = -1
                            # chosen_ack_uniflow = None
                            chosen_ack_builder = None

            # filter the uniflows that can't send at this time
            for uniflow_id in paced_uniflows:
                self._builder_manager.finish_builder(uniflow_id)

            if self._builder_manager.length_active_builders() == 0:
                break

            # print("active builders after pacing:", self._builder_manager.length_active_builders())

            # start a new packet for each uniflow
            for item in self._builder_manager.builders.items():
                # uniflow_id = item[0]
                # auniflow = item[1][0]
                builder = item[1][1]
                builder.start_packet(packet_type, crypto)

            if self._handshake_complete:
                # ACK
                space = iruniflow.receiving_spaces[tls.Epoch.ONE_RTT]
                if (
                    space.ack_at is not None
                    and space.ack_at <= now
                    and chosen_ack_uniflow_id != -1
                ):
                    # print("sending ACK", 0, "over uniflow", chosen_ack_uniflow_id)
                    self._write_ack_frame(
                        builder=chosen_ack_builder, space=space, now=now
                    )

                # HANDSHAKE_DONE
                if self._handshake_done_pending:
                    item = self._builder_manager.get_builder()
                    # print("sending HANDSHAKE_DONE over uniflow", item[0])
                    handshake_builder = item[1][1]
                    self._write_handshake_done_frame(builder=handshake_builder)
                    self._handshake_done_pending = False

                # PATH_CHALLENGE
                # only perform these on sending uniflow 0
                # Other uniflows should perform path challenges differently
                item = self._builder_manager.get_specific_builder(0)
                if item is not None:
                    selected_uniflow = item[1][0]
                    challenge_builder = item[1][1]
                    if (
                        not selected_uniflow.path_is_validated
                        and selected_uniflow.local_challenge is None
                    ):
                        # print("sending PATH_CHALLENGE over uniflow", selected_uniflow.uniflow_id)
                        challenge = os.urandom(8)
                        self._write_path_challenge_frame(
                            builder=challenge_builder, challenge=challenge, uniflow_id=0
                        )
                        selected_uniflow.local_challenge = challenge

                # PATH_RESPONSE
                for runiflow in self._receiving_uniflows.values():
                    if runiflow.remote_challenge is not None:
                        item = self._builder_manager.get_builder()
                        # print("sending PATH_RESPONSE over uniflow", item[0])
                        response_builder = item[1][1]
                        self._write_path_response_frame(
                            builder=response_builder,
                            challenge=runiflow.remote_challenge,
                        )
                    runiflow.remote_challenge = None

                # NEW_CONNECTION_ID
                riuniflow = self._receiving_uniflows[0]
                for connection_id in riuniflow.cid_available:
                    if not connection_id.was_sent:
                        item = self._builder_manager.get_builder()
                        # print("sending NEW_CONNECTION_ID over uniflow", item[0])
                        new_cid_builder = item[1][1]
                        self._write_new_connection_id_frame(
                            builder=new_cid_builder, connection_id=connection_id
                        )

                # RETIRE_CONNECTION_ID
                siuniflow = self._sending_uniflows[0]
                while siuniflow.retire_connection_ids:
                    item = self._builder_manager.get_builder()
                    # print("sending RETIRE_CONNECTION_ID over uniflow", item[0])
                    ret_cid_builder = item[1][1]
                    sequence_number = siuniflow.retire_connection_ids.pop(0)
                    self._write_retire_connection_id_frame(
                        builder=ret_cid_builder, sequence_number=sequence_number
                    )

                # MP frames
                if self._peer_mp_support and self._max_sending_uniflows_id is not None:
                    # MP_NEW_CONNECTION_ID
                    for runiflow in self._receiving_uniflows.values():
                        if runiflow.uniflow_id != 0:
                            for connection_id in runiflow.cid_available:
                                if not connection_id.was_sent:
                                    item = self._builder_manager.get_builder()
                                    # print("sending MP_NEW_CONNECTION_ID over uniflow", item[0])
                                    mp_new_cid_builder = item[1][1]
                                    self._write_mp_new_connection_id_frame(
                                        builder=mp_new_cid_builder,
                                        connection_id=connection_id,
                                        uniflow_id=runiflow.uniflow_id,
                                    )

                    # MP_RETIRE_CONNECTION_ID
                    for suniflow in self._sending_uniflows.values():
                        if suniflow.uniflow_id != 0:
                            while suniflow.retire_connection_ids:
                                item = self._builder_manager.get_builder()
                                # print("sending MP_RETIRE_CONNECTION_ID over uniflow", item[0])
                                mp_ret_cid_builder = item[1][1]
                                sequence_number = suniflow.retire_connection_ids.pop(0)
                                self._write_mp_retire_connection_id_frame(
                                    builder=mp_ret_cid_builder,
                                    sequence_number=sequence_number,
                                    uniflow_id=suniflow.uniflow_id,
                                )

                    # MP_ACK
                    if chosen_ack_uniflow_id != -1:
                        for runiflow in self._receiving_uniflows.values():
                            if runiflow.uniflow_id != 0:
                                mpspace = runiflow.receiving_spaces[tls.Epoch.ONE_RTT]
                                if mpspace.ack_at is not None and mpspace.ack_at <= now:
                                    # print("sending MP_ACK", runiflow.uniflow_id, "over uniflow", chosen_ack_uniflow_id)
                                    self._write_mp_ack_frame(
                                        builder=chosen_ack_builder,
                                        space=mpspace,
                                        now=now,
                                        uniflow_id=runiflow.uniflow_id,
                                    )

                    # ADD_ADDRESS
                    for laddr in self._local_addresses.values():
                        if not laddr.was_sent:
                            item = self._builder_manager.get_builder()
                            # print("sending ADD_ADDRESS over uniflow", item[0])
                            add_addr_builder = item[1][1]
                            self._write_add_address_frame(
                                builder=add_addr_builder, address=laddr
                            )

                    # REMOVE_ADDRESS
                    while self._removed_addresses:
                        item = self._builder_manager.get_builder()
                        # print("sending REMOVE_ADDRESS over uniflow", item[0])
                        rem_addr_builder = item[1][1]
                        address_id = self._removed_addresses.pop(0)
                        self._write_remove_address_frame(
                            builder=rem_addr_builder,
                            address=self._local_addresses[address_id],
                        )

                    # UNIFLOWS
                    if self._uniflows_pending:
                        item = self._builder_manager.get_builder()
                        # print("sending UNIFLOWS over uniflow", item[0])
                        uniflows_builder = item[1][1]
                        self._uniflows_pending = False
                        self._write_uniflows_frame(
                            builder=uniflows_builder, sequence_number=self._uniflows_seq
                        )

                # STREAMS_BLOCKED
                if self._streams_blocked_pending:
                    if self._streams_blocked_bidi:
                        item = self._builder_manager.get_builder()
                        # print("sending STREAMS_BLOCKED_BIDI over uniflow", item[0])
                        str_b_bidi_builder = item[1][1]
                        self._write_streams_blocked_frame(
                            builder=str_b_bidi_builder,
                            frame_type=QuicFrameType.STREAMS_BLOCKED_BIDI,
                            limit=self._remote_max_streams_bidi,
                        )
                    if self._streams_blocked_uni:
                        item = self._builder_manager.get_builder()
                        # print("sending STREAMS_BLOCKED_UNI over uniflow", item[0])
                        str_b_uni_builder = item[1][1]
                        self._write_streams_blocked_frame(
                            builder=str_b_uni_builder,
                            frame_type=QuicFrameType.STREAMS_BLOCKED_UNI,
                            limit=self._remote_max_streams_uni,
                        )
                    self._streams_blocked_pending = False

                # MAX_DATA and MAX_STREAMS
                space = iruniflow.receiving_spaces[tls.Epoch.ONE_RTT]
                self._write_connection_limits(space=space)

            # stream-level limits
            for stream in self._streams.values():
                stream_space = iruniflow.receiving_spaces[tls.Epoch.ONE_RTT]
                self._write_stream_limits(
                    builders=self._builder_manager.builders,
                    space=stream_space,
                    stream=stream,
                )

            # PING (user-request)
            if self._ping_pending:
                item = self._builder_manager.get_builder()
                # print("sending PING over uniflow", item[0])
                ping_builder = item[1][1]
                self._write_ping_frame(ping_builder, self._ping_pending)
                self._ping_pending.clear()

            # PING (probe)
            for item in self._builder_manager.builders.items():
                selected_uniflow = item[1][0]
                probe_builder = item[1][1]
                if selected_uniflow.probe_pending:
                    # print("sending PROBE over uniflow", item[0])
                    self._write_ping_frame(probe_builder, comment="probe")
                    selected_uniflow.probe_pending = False

            # CRYPTO
            if crypto_stream is not None and not crypto_stream.send_buffer_is_empty:
                item = self._builder_manager.get_builder()
                # print("sending CRYPTO over uniflow", item[0])
                crypto_builder = item[1][1]
                crypto_space = iruniflow.receiving_spaces[tls.Epoch.ONE_RTT]
                used_builder = self._write_crypto_frame(
                    builder=crypto_builder, space=crypto_space, stream=crypto_stream
                )
                if not used_builder:
                    self._builder_manager.restore_builder()

            # DATAGRAM
            dgram_pot_builders: List[int] = []
            for item in self._builder_manager.builders.items():
                dgram_pot_builders.append(item[0])
            while self._datagrams_pending and len(dgram_pot_builders) > 0:
                item = self._builder_manager.get_specific_builder(dgram_pot_builders[0])
                # print("sending DATAGRAM over uniflow", item[0])
                datagram_builder = item[1][1]
                try:
                    self._write_datagram_frame(
                        builder=datagram_builder,
                        data=self._datagrams_pending[0],
                        frame_type=QuicFrameType.DATAGRAM_WITH_LENGTH,
                    )
                    self._datagrams_pending.popleft()
                except QuicPacketBuilderStop:
                    # print("restore")
                    del dgram_pot_builders[0]

            # STREAM and RESET_STREAM
            for stream in self._streams.values():
                if stream.reset_pending:
                    item = self._builder_manager.get_builder()
                    # print("sending RESET_STREAM over uniflow", item[0])
                    reset_str_builder = item[1][1]
                    self._write_reset_stream_frame(
                        builder=reset_str_builder,
                        frame_type=QuicFrameType.RESET_STREAM,
                        stream=stream,
                    )
                elif not stream.is_blocked and not stream.send_buffer_is_empty:
                    str_pot_builders: List[int] = []
                    for item in self._builder_manager.builders.items():
                        str_pot_builders.append(item[0])
                    while (
                        not stream.is_blocked
                        and not stream.send_buffer_is_empty
                        and len(str_pot_builders) > 0
                    ):
                        item = self._builder_manager.get_specific_builder(
                            str_pot_builders[0]
                        )
                        # print("sending STREAM over uniflow", item[0])
                        str_builder = item[1][1]
                        str_space = iruniflow.receiving_spaces[tls.Epoch.ONE_RTT]
                        data_used = self._write_stream_frame(
                            builder=str_builder,
                            space=str_space,
                            stream=stream,
                            max_offset=min(
                                stream._send_highest
                                + self._remote_max_data
                                - self._remote_max_data_used,
                                stream.max_stream_data_remote,
                            ),
                        )
                        self._remote_max_data_used += data_used
                        # print("stream data", data_used)
                        if data_used == 0:
                            del str_pot_builders[0]

            for uniflow_id, (auniflow, builder) in list(
                self._builder_manager.builders.items()
            ):
                if builder.packet_is_empty:
                    # print("builder", uniflow_id, "was empty")
                    self._builder_manager.finish_builder(uniflow_id)
                else:
                    auniflow.loss._pacer.update_after_send(now=now)

            # print("end loop")

        builders = self._builder_manager.end_manager()
        return builders

    def _write_handshake(
        self, builder: QuicPacketBuilder, epoch: tls.Epoch, now: float
    ) -> None:
        crypto = self._cryptos[epoch]
        if not crypto.send.is_valid():
            return

        crypto_stream = self._crypto_streams[epoch]
        space = self._receiving_uniflows[0].receiving_spaces[epoch]

        while True:
            if epoch == tls.Epoch.INITIAL:
                packet_type = PACKET_TYPE_INITIAL
            else:
                packet_type = PACKET_TYPE_HANDSHAKE
            builder.start_packet(packet_type, crypto)

            # ACK
            if space.ack_at is not None:
                # print("sending ACK", 0, "over uniflow", 0)
                self._write_ack_frame(builder=builder, space=space, now=now)

            # CRYPTO
            if not crypto_stream.send_buffer_is_empty:
                if self._write_crypto_frame(
                    builder=builder, space=space, stream=crypto_stream
                ):
                    # print("sending CRYPTO over uniflow", 0)
                    self._sending_uniflows[0].probe_pending = False

            # PING (probe)
            if (
                self._sending_uniflows[0].probe_pending
                and not self._handshake_complete
                and (
                    epoch == tls.Epoch.HANDSHAKE
                    or not self._cryptos[tls.Epoch.HANDSHAKE].send.is_valid()
                )
            ):
                # print("sending PING over uniflow", 0)
                self._write_ping_frame(builder, comment="probe")
                self._sending_uniflows[0].probe_pending = False

            if builder.packet_is_empty:
                break

    def _write_ack_frame(
        self, builder: QuicPacketBuilder, space: QuicReceivingPacketSpace, now: float
    ) -> None:
        # calculate ACK delay
        ack_delay = now - space.largest_received_time
        ack_delay_encoded = int(ack_delay * 1000000) >> self._local_ack_delay_exponent

        buf = builder.start_frame(
            QuicFrameType.ACK,
            capacity=ACK_FRAME_CAPACITY,
            handler=self._on_ack_delivery,
            handler_args=(space, space.largest_received_packet),
        )
        ranges = push_ack_frame(buf, space.ack_queue, ack_delay_encoded)
        space.ack_at = None

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_ack_frame(
                    ranges=space.ack_queue, delay=ack_delay
                )
            )

        # check if we need to trigger an ACK-of-ACK
        if ranges > 1 and builder.packet_number % 8 == 0:
            self._write_ping_frame(builder, comment="ACK-of-ACK trigger")

    def _write_connection_close_frame(
        self,
        builder: QuicPacketBuilder,
        epoch: tls.Epoch,
        error_code: int,
        frame_type: Optional[int],
        reason_phrase: str,
    ) -> None:
        # convert application-level close to transport-level close in early stages
        if frame_type is None and epoch in (tls.Epoch.INITIAL, tls.Epoch.HANDSHAKE):
            error_code = QuicErrorCode.APPLICATION_ERROR
            frame_type = QuicFrameType.PADDING
            reason_phrase = ""

        reason_bytes = reason_phrase.encode("utf8")
        reason_length = len(reason_bytes)

        if frame_type is None:
            buf = builder.start_frame(
                QuicFrameType.APPLICATION_CLOSE,
                capacity=APPLICATION_CLOSE_FRAME_CAPACITY + reason_length,
            )
            buf.push_uint_var(error_code)
            buf.push_uint_var(reason_length)
            buf.push_bytes(reason_bytes)
        else:
            buf = builder.start_frame(
                QuicFrameType.TRANSPORT_CLOSE,
                capacity=TRANSPORT_CLOSE_FRAME_CAPACITY + reason_length,
            )
            buf.push_uint_var(error_code)
            buf.push_uint_var(frame_type)
            buf.push_uint_var(reason_length)
            buf.push_bytes(reason_bytes)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_connection_close_frame(
                    error_code=error_code,
                    frame_type=frame_type,
                    reason_phrase=reason_phrase,
                )
            )

    def _write_connection_limits(self, space: QuicReceivingPacketSpace) -> None:
        """
        Raise MAX_DATA or MAX_STREAMS if needed.
        """
        for limit in (
            self._local_max_data,
            self._local_max_streams_bidi,
            self._local_max_streams_uni,
        ):
            if limit.used * 2 > limit.value:
                limit.value *= 2
                self._logger.debug("Local %s raised to %d", limit.name, limit.value)
            if limit.value != limit.sent:
                item = self._builder_manager.get_builder()
                # print("sending MAX_DATA/MAX_STREAMS over uniflow", item[0])
                max_builder = item[1][1]
                buf = max_builder.start_frame(
                    limit.frame_type,
                    capacity=CONNECTION_LIMIT_FRAME_CAPACITY,
                    handler=self._on_connection_limit_delivery,
                    handler_args=(limit,),
                )
                buf.push_uint_var(limit.value)
                limit.sent = limit.value

                # log frame
                if self._quic_logger is not None:
                    max_builder.quic_logger_frames.append(
                        self._quic_logger.encode_connection_limit_frame(
                            frame_type=limit.frame_type,
                            maximum=limit.value,
                        )
                    )

    def _write_crypto_frame(
        self,
        builder: QuicPacketBuilder,
        space: QuicReceivingPacketSpace,
        stream: QuicStream,
    ) -> bool:
        frame_overhead = 3 + size_uint_var(stream.next_send_offset)
        frame = stream.get_frame(builder.remaining_flight_space - frame_overhead)
        if frame is not None:
            buf = builder.start_frame(
                QuicFrameType.CRYPTO,
                capacity=frame_overhead,
                handler=stream.on_data_delivery,
                handler_args=(frame.offset, frame.offset + len(frame.data)),
            )
            buf.push_uint_var(frame.offset)
            buf.push_uint16(len(frame.data) | 0x4000)
            buf.push_bytes(frame.data)

            # log frame
            if self._quic_logger is not None:
                builder.quic_logger_frames.append(
                    self._quic_logger.encode_crypto_frame(frame)
                )
            return True

        return False

    def _write_datagram_frame(
        self, builder: QuicPacketBuilder, data: bytes, frame_type: QuicFrameType
    ) -> bool:
        """
        Write a DATAGRAM frame.

        Returns True if the frame was processed, False otherwise.
        """
        assert frame_type == QuicFrameType.DATAGRAM_WITH_LENGTH
        length = len(data)
        frame_size = 1 + size_uint_var(length) + length

        buf = builder.start_frame(frame_type, capacity=frame_size)
        buf.push_uint_var(length)
        buf.push_bytes(data)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_datagram_frame(length=length)
            )

        return True

    def _write_handshake_done_frame(self, builder: QuicPacketBuilder) -> None:
        builder.start_frame(
            QuicFrameType.HANDSHAKE_DONE,
            capacity=HANDSHAKE_DONE_FRAME_CAPACITY,
            handler=self._on_handshake_done_delivery,
        )

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_handshake_done_frame()
            )

    def _write_new_connection_id_frame(
        self, builder: QuicPacketBuilder, connection_id: QuicConnectionId
    ) -> None:
        retire_prior_to = 0  # FIXME

        buf = builder.start_frame(
            QuicFrameType.NEW_CONNECTION_ID,
            capacity=NEW_CONNECTION_ID_FRAME_CAPACITY,
            handler=self._on_new_connection_id_delivery,
            handler_args=(connection_id,),
        )
        buf.push_uint_var(connection_id.sequence_number)
        buf.push_uint_var(retire_prior_to)
        buf.push_uint8(len(connection_id.cid))
        buf.push_bytes(connection_id.cid)
        buf.push_bytes(connection_id.stateless_reset_token)

        connection_id.was_sent = True
        self._events.append(events.ConnectionIdIssued(connection_id=connection_id.cid))

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_new_connection_id_frame(
                    connection_id=connection_id.cid,
                    retire_prior_to=retire_prior_to,
                    sequence_number=connection_id.sequence_number,
                    stateless_reset_token=connection_id.stateless_reset_token,
                )
            )

    def _write_path_challenge_frame(
        self, builder: QuicPacketBuilder, challenge: bytes, uniflow_id: int
    ) -> None:
        buf = builder.start_frame(
            QuicFrameType.PATH_CHALLENGE,
            capacity=PATH_CHALLENGE_FRAME_CAPACITY,
            handler=self._on_path_challenge_delivery,
            handler_args=(challenge, uniflow_id),
        )
        buf.push_bytes(challenge)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_path_challenge_frame(data=challenge)
            )

    def _write_path_response_frame(
        self, builder: QuicPacketBuilder, challenge: bytes
    ) -> None:
        buf = builder.start_frame(
            QuicFrameType.PATH_RESPONSE, capacity=PATH_RESPONSE_FRAME_CAPACITY
        )
        buf.push_bytes(challenge)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_path_response_frame(data=challenge)
            )

    def _write_ping_frame(
        self, builder: QuicPacketBuilder, uids: List[int] = [], comment=""
    ):
        builder.start_frame(
            QuicFrameType.PING,
            capacity=PING_FRAME_CAPACITY,
            handler=self._on_ping_delivery,
            handler_args=(tuple(uids),),
        )
        self._logger.debug(
            "Sending PING%s in packet %d",
            " (%s)" % comment if comment else "",
            builder.packet_number,
        )

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(self._quic_logger.encode_ping_frame())

    def _write_reset_stream_frame(
        self,
        builder: QuicPacketBuilder,
        frame_type: QuicFrameType,
        stream: QuicStream,
    ) -> None:
        buf = builder.start_frame(
            frame_type=frame_type,
            capacity=RESET_STREAM_CAPACITY,
            handler=stream.on_reset_delivery,
        )
        reset = stream.get_reset_frame()
        buf.push_uint_var(stream.stream_id)
        buf.push_uint_var(reset.error_code)
        buf.push_uint_var(reset.final_size)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_reset_stream_frame(
                    error_code=reset.error_code,
                    final_size=reset.final_size,
                    stream_id=stream.stream_id,
                )
            )

    def _write_retire_connection_id_frame(
        self, builder: QuicPacketBuilder, sequence_number: int
    ) -> None:
        buf = builder.start_frame(
            QuicFrameType.RETIRE_CONNECTION_ID,
            capacity=RETIRE_CONNECTION_ID_CAPACITY,
            handler=self._on_retire_connection_id_delivery,
            handler_args=(sequence_number,),
        )
        buf.push_uint_var(sequence_number)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_retire_connection_id_frame(sequence_number)
            )

    def _write_stream_frame(
        self,
        builder: QuicPacketBuilder,
        space: QuicReceivingPacketSpace,
        stream: QuicStream,
        max_offset: int,
    ) -> int:
        # the frame data size is constrained by our peer's MAX_DATA and
        # the space available in the current packet
        frame_overhead = (
            3
            + size_uint_var(stream.stream_id)
            + (size_uint_var(stream.next_send_offset) if stream.next_send_offset else 0)
        )
        previous_send_highest = stream._send_highest
        frame = stream.get_frame(
            builder.remaining_flight_space - frame_overhead, max_offset
        )

        if frame is not None:
            frame_type = QuicFrameType.STREAM_BASE | 2  # length
            if frame.offset:
                frame_type |= 4
            if frame.fin:
                frame_type |= 1
            buf = builder.start_frame(
                frame_type,
                capacity=frame_overhead,
                handler=stream.on_data_delivery,
                handler_args=(frame.offset, frame.offset + len(frame.data)),
            )
            buf.push_uint_var(stream.stream_id)
            if frame.offset:
                buf.push_uint_var(frame.offset)
            buf.push_uint16(len(frame.data) | 0x4000)
            buf.push_bytes(frame.data)

            # log frame
            if self._quic_logger is not None:
                builder.quic_logger_frames.append(
                    self._quic_logger.encode_stream_frame(
                        frame, stream_id=stream.stream_id
                    )
                )

            return stream._send_highest - previous_send_highest
        else:
            return 0

    def _write_stream_limits(
        self,
        builders: Dict[int, Tuple[QuicSendingUniflow, QuicPacketBuilder]],
        space: QuicReceivingPacketSpace,
        stream: QuicStream,
    ) -> None:
        """
        Raise MAX_STREAM_DATA if needed.

        The only case where `stream.max_stream_data_local` is zero is for
        locally created unidirectional streams. We skip such streams to avoid
        spurious logging.
        """
        if (
            stream.max_stream_data_local
            and stream._recv_highest * 2 > stream.max_stream_data_local
        ):
            stream.max_stream_data_local *= 2
            self._logger.debug(
                "Stream %d local max_stream_data raised to %d",
                stream.stream_id,
                stream.max_stream_data_local,
            )
        if stream.max_stream_data_local_sent != stream.max_stream_data_local:
            for item in builders.items():
                # print("sending MAX_STREAM_DATA over uniflow", item[0])
                builder = item[1][1]
                buf = builder.start_frame(
                    QuicFrameType.MAX_STREAM_DATA,
                    capacity=MAX_STREAM_DATA_FRAME_CAPACITY,
                    handler=self._on_max_stream_data_delivery,
                    handler_args=(stream,),
                )
                buf.push_uint_var(stream.stream_id)
                buf.push_uint_var(stream.max_stream_data_local)
                stream.max_stream_data_local_sent = stream.max_stream_data_local

                # log frame
                if self._quic_logger is not None:
                    builder.quic_logger_frames.append(
                        self._quic_logger.encode_max_stream_data_frame(
                            maximum=stream.max_stream_data_local,
                            stream_id=stream.stream_id,
                        )
                    )

    def _write_streams_blocked_frame(
        self, builder: QuicPacketBuilder, frame_type: QuicFrameType, limit: int
    ) -> None:
        buf = builder.start_frame(frame_type, capacity=STREAMS_BLOCKED_CAPACITY)
        buf.push_uint_var(limit)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_streams_blocked_frame(
                    is_unidirectional=frame_type == QuicFrameType.STREAMS_BLOCKED_UNI,
                    limit=limit,
                )
            )

    def _write_mp_new_connection_id_frame(
        self,
        builder: QuicPacketBuilder,
        connection_id: QuicConnectionId,
        uniflow_id: int,
    ) -> None:
        retire_prior_to = 0  # FIXME

        buf = builder.start_frame(
            QuicFrameType.MP_NEW_CONNECTION_ID,
            capacity=MP_NEW_CONNECTION_ID_FRAME_CAPACITY,
            handler=self._on_mp_new_connection_id_delivery,
            handler_args=(
                connection_id,
                uniflow_id,
            ),
        )
        buf.push_uint_var(uniflow_id)
        buf.push_uint_var(connection_id.sequence_number)
        buf.push_uint_var(retire_prior_to)
        buf.push_uint8(len(connection_id.cid))
        buf.push_bytes(connection_id.cid)
        buf.push_bytes(connection_id.stateless_reset_token)

        connection_id.was_sent = True
        self._events.append(
            events.MPConnectionIdIssued(
                connection_id=connection_id.cid, uniflow_id=uniflow_id
            )
        )

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_mp_new_connection_id_frame(
                    connection_id=connection_id.cid,
                    uniflow_id=uniflow_id,
                    retire_prior_to=retire_prior_to,
                    sequence_number=connection_id.sequence_number,
                    stateless_reset_token=connection_id.stateless_reset_token,
                )
            )

    def _write_mp_retire_connection_id_frame(
        self, builder: QuicPacketBuilder, sequence_number: int, uniflow_id: int
    ) -> None:
        buf = builder.start_frame(
            QuicFrameType.MP_RETIRE_CONNECTION_ID,
            capacity=MP_RETIRE_CONNECTION_ID_CAPACITY,
            handler=self._on_mp_retire_connection_id_delivery,
            handler_args=(
                sequence_number,
                uniflow_id,
            ),
        )
        buf.push_uint_var(uniflow_id)
        buf.push_uint_var(sequence_number)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_mp_retire_connection_id_frame(
                    uniflow_id=uniflow_id, sequence_number=sequence_number
                )
            )

    def _write_mp_ack_frame(
        self,
        builder: QuicPacketBuilder,
        space: QuicReceivingPacketSpace,
        now: float,
        uniflow_id: int,
    ) -> None:
        # calculate ACK delay
        ack_delay = now - space.largest_received_time
        ack_delay_encoded = int(ack_delay * 1000000) >> self._local_ack_delay_exponent

        buf = builder.start_frame(
            QuicFrameType.MP_ACK,
            capacity=MP_ACK_FRAME_CAPACITY,
            handler=self._on_mp_ack_delivery,
            handler_args=(space, space.largest_received_packet),
        )

        buf.push_uint_var(uniflow_id)
        ranges = push_ack_frame(buf, space.ack_queue, ack_delay_encoded)
        space.ack_at = None

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_mp_ack_frame(
                    uniflow_id=uniflow_id, ranges=space.ack_queue, delay=ack_delay
                )
            )

        # check if we need to trigger an ACK-of-ACK
        if ranges > 1 and builder.packet_number % 8 == 0:
            self._write_ping_frame(builder, comment="ACK-of-ACK trigger")

    def _write_add_address_frame(
        self, builder: QuicPacketBuilder, address: EndpointAddress
    ) -> None:
        frame_overhead = 2 + 1 + 1 + 8 + 1
        if address.ip_version == IPVersion.IPV4:
            frame_overhead += 4
        else:
            frame_overhead += 16
        buf = builder.start_frame(
            QuicFrameType.ADD_ADDRESS,
            capacity=frame_overhead,
            handler=self._on_add_address_delivery,
            handler_args=(address.address_id,),
        )
        first_byte = 0
        if address.port:
            first_byte |= 16
        first_byte |= int(address.ip_version)
        interface = int(address.interface_type)
        buf.push_uint8(first_byte)
        buf.push_uint8(address.address_id)
        buf.push_uint_var(address.sequence_number)
        buf.push_uint8(interface)
        version = (
            socket.AF_INET if address.ip_version == IPVersion.IPV4 else socket.AF_INET6
        )
        ip_bytes = socket.inet_pton(version, address.ip_address)
        buf.push_bytes(ip_bytes)
        if address.port:
            buf.push_uint16(address.port)
        address.was_sent = True

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_add_address_frame(
                    address_id=address.address_id,
                    sequence_number=address.sequence_number,
                    interface_type=int(address.interface_type),
                    ip_version=int(address.ip_version),
                    ip_address=address.ip_address,
                    port=address.port,
                )
            )

    def _write_remove_address_frame(
        self, builder: QuicPacketBuilder, address: EndpointAddress
    ) -> None:
        buf = builder.start_frame(
            QuicFrameType.REMOVE_ADDRESS,
            capacity=REMOVE_ADDRESS_CAPACITY,
            handler=self._on_remove_address_delivery,
            handler_args=(address.address_id,),
        )
        buf.push_uint8(address.address_id)
        buf.push_uint_var(address.sequence_number)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_remove_address_frame(
                    address_id=address.address_id,
                    sequence_number=address.sequence_number,
                )
            )

    def _write_uniflows_frame(
        self, builder: QuicPacketBuilder, sequence_number: int
    ) -> None:
        frame_overhead = 1 + 8 + 8 + 8

        usable_runiflows = []
        for runiflow in self._receiving_uniflows.values():
            if runiflow.source_address is not None:
                usable_runiflows.append(
                    {
                        "uniflow_id": runiflow.uniflow_id,
                        "local_address_id": runiflow.destination_address.address_id,
                    }
                )
                frame_overhead += 8 + 1

        usable_suniflows = []
        for suniflow in self._sending_uniflows.values():
            if suniflow.state == UniflowState.ACTIVE:
                usable_suniflows.append(
                    {
                        "uniflow_id": suniflow.uniflow_id,
                        "local_address_id": suniflow.source_address.address_id,
                    }
                )
                frame_overhead += 8 + 1
        buf = builder.start_frame(
            QuicFrameType.UNIFLOWS,
            capacity=frame_overhead,
            handler=self._on_uniflows_delivery,
        )

        buf.push_uint_var(sequence_number)
        buf.push_uint_var(len(usable_runiflows))
        buf.push_uint_var(len(usable_suniflows))

        for uruniflow in usable_runiflows:
            buf.push_uint_var(uruniflow["uniflow_id"])
            buf.push_uint8(uruniflow["local_address_id"])

        for usuniflow in usable_suniflows:
            buf.push_uint_var(usuniflow["uniflow_id"])
            buf.push_uint8(usuniflow["local_address_id"])

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_uniflows_frame(
                    sequence_number=sequence_number,
                    receiving_uniflows=usable_runiflows,
                    active_sending_uniflows=usable_suniflows,
                )
            )


class BuilderManager:
    """
    A _write_application builder manager.

    The class provides an interface to help the _write_application method in QuicConnection-class
    This class implements a Round-Robin mechanism on frame-level
    """

    def __init__(self) -> None:
        self._builders: Dict[int, Tuple[QuicSendingUniflow, QuicPacketBuilder]] = {}
        self._fin_builders: Dict[int, Tuple[QuicSendingUniflow, QuicPacketBuilder]] = {}
        self._selected_index: int = -1
        self._active: bool = False

    def start_manager(
        self, builders: Dict[int, Tuple[QuicSendingUniflow, QuicPacketBuilder]]
    ) -> None:
        """
        Start the manager by loading the available buffers, along with related info

        :param builders: The available builders for the current run of _write_application
        """
        self._builders = builders
        self._fin_builders = {}
        self._selected_index = -1
        self._active = True

    def length_active_builders(self) -> int:
        return len(self._builders.items())

    @property
    def builders(self) -> Dict[int, Tuple[QuicSendingUniflow, QuicPacketBuilder]]:
        return self._builders

    def finish_builder(self, uniflow_id: int) -> None:
        """
        Retire a certain builder from being used in the current run of _write_application
        :param uniflow_id: The uniflow id to which the buffer is tied
        """
        assert self._active
        item = self._builders[uniflow_id]
        self._fin_builders[uniflow_id] = item
        del self._builders[uniflow_id]

    def get_builder(self) -> Tuple[int, Tuple[QuicSendingUniflow, QuicPacketBuilder]]:
        """
        Get the next builder based on the Round-Robin mechanism
        """
        assert self._active
        self._selected_index += 1
        if self._selected_index >= len(self._builders.keys()):
            self._selected_index = 0
        dict_key = list(self._builders.keys())[self._selected_index]
        # print(self._builders.keys())
        # print("id:", self._selected_index, "dict key:", dict_key)
        return dict_key, self._builders[dict_key]

    def get_specific_builder(
        self, uniflow_id: int
    ) -> Optional[Tuple[int, Tuple[QuicSendingUniflow, QuicPacketBuilder]]]:
        """
        Get a specific builder to perform certain non Round-Robin based actions
        :param uniflow_id the uniflow id to which te builder is tied
        """
        assert self._active
        if uniflow_id in self._builders.keys():
            return uniflow_id, self.builders[uniflow_id]
        else:
            return None

    def restore_builder(self) -> None:
        """
        Undo the last action of the Round-Robin mechanism
        """
        assert self._active
        # print("restored")
        self._selected_index -= 1
        if self._selected_index < 0:
            self._selected_index = len(self._builders.keys()) - 1

    def end_manager(self) -> Dict[int, Tuple[QuicSendingUniflow, QuicPacketBuilder]]:
        """
        Reset all the private members and return all buffers as retired
        """
        assert len(self._builders.items()) == 0
        self._builders = {}
        builders = self._fin_builders
        self._fin_builders = {}
        self._selected_index = -1
        self._active = False
        return builders
