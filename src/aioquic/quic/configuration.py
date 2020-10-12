from dataclasses import dataclass, field
from os import PathLike
from typing import Any, List, Optional, TextIO, Union

from ..tls import (
    CipherSuite,
    SessionTicket,
    load_pem_private_key,
    load_pem_x509_certificates,
)
from .logger import QuicLogger
from .packet import QuicProtocolVersion
from .recovery import CCTYPE


@dataclass
class QuicConfiguration:
    """
    A QUIC configuration.
    """

    alpn_protocols: Optional[List[str]] = None
    """
    A list of supported ALPN protocols.
    """

    connection_id_length: int = 8
    """
    The length in bytes of local connection IDs.
    """

    idle_timeout: float = 60.0
    """
    The idle timeout in seconds.

    The connection is terminated if nothing is received for the given duration.
    """

    is_client: bool = True
    """
    Whether this is the client side of the QUIC connection.
    """

    max_data: int = 1048576
    """
    Connection-wide flow control limit.
    """

    max_stream_data: int = 1048576
    """
    Per-stream flow control limit.
    """

    max_sending_uniflow_id: Optional[int] = 0
    """
    Connection-wide number of sending uniflows
    """

    quic_logger: Optional[QuicLogger] = None
    """
    The :class:`~aioquic.quic.logger.QuicLogger` instance to log events to.
    """

    secrets_log_file: TextIO = None
    """
    A file-like object in which to log traffic secrets.

    This is useful to analyze traffic captures with Wireshark.
    """

    server_name: Optional[str] = None
    """
    The server name to send during the TLS handshake the Server Name Indication.

    .. note:: This is only used by clients.
    """

    local_addresses: List = field(default_factory=list)
    """
    The available addresses of a host
    """

    cc_type: CCTYPE = CCTYPE.NEW_RENO
    """
    The congestion controller to be used
    """

    session_ticket: Optional[SessionTicket] = None
    """
    The TLS session ticket which should be used for session resumption.
    """

    cadata: Optional[bytes] = None
    cafile: Optional[str] = None
    capath: Optional[str] = None
    certificate: Any = None
    certificate_chain: List[Any] = field(default_factory=list)
    cipher_suites: Optional[List[CipherSuite]] = None
    initial_rtt: float = 0.1
    max_datagram_frame_size: Optional[int] = None
    private_key: Any = None
    quantum_readiness_test: bool = False
    supported_versions: List[int] = field(
        default_factory=lambda: [
            QuicProtocolVersion.DRAFT_29,
            QuicProtocolVersion.DRAFT_28,
            QuicProtocolVersion.DRAFT_27,
        ]
    )
    verify_mode: Optional[int] = None

    def load_cert_chain(
        self,
        certfile: PathLike,
        keyfile: Optional[PathLike] = None,
        password: Optional[Union[bytes, str]] = None,
    ) -> None:
        """
        Load a private key and the corresponding certificate.
        """
        with open(certfile, "rb") as fp:
            certificates = load_pem_x509_certificates(fp.read())
        self.certificate = certificates[0]
        self.certificate_chain = certificates[1:]

        if keyfile is not None:
            with open(keyfile, "rb") as fp:
                self.private_key = load_pem_private_key(
                    fp.read(),
                    password=password.encode("utf8")
                    if isinstance(password, str)
                    else password,
                )

    def load_verify_locations(
        self,
        cafile: Optional[str] = None,
        capath: Optional[str] = None,
        cadata: Optional[bytes] = None,
    ) -> None:
        """
        Load a set of "certification authority" (CA) certificates used to
        validate other peers' certificates.
        """
        self.cafile = cafile
        self.capath = capath
        self.cadata = cadata
