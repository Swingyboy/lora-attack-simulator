from __future__ import annotations

import socket

from lora_attack_toolkit.transport.errors import (
    DnsResolutionError,
    TemporaryNetworkError,
    TransportUnavailableError,
)
from lora_attack_toolkit.transport.transport import TransportClient


class UdpTransport(TransportClient):
    """Semtech UDP transport client.

    Hostname resolution is performed once in :meth:`connect` and the resolved
    IP address is cached for the lifetime of the connection.  This avoids
    repeated DNS lookups on every :meth:`send` call and prevents spurious
    failures from transient DNS unavailability during an active session.

    On reconnect the hostname is re-resolved so that address changes are
    picked up without restarting the session.
    """

    def __init__(self, host: str, port: int) -> None:
        self._host = host
        self._port = port
        self._resolved_addr: tuple[str, int] | None = None
        self._socket: socket.socket | None = None

    def connect(self) -> None:
        self._resolved_addr = self._resolve_address()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.1)
        self._socket = sock

    def disconnect(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        self._resolved_addr = None

    def send(self, payload: bytes) -> None:
        if self._socket is None or self._resolved_addr is None:
            raise TransportUnavailableError("UDP transport is not connected")
        try:
            self._socket.sendto(payload, self._resolved_addr)
        except OSError as exc:
            raise TemporaryNetworkError(f"UDP send failed: {exc}") from exc

    def receive(self, timeout_sec: float) -> bytes | None:
        if self._socket is None:
            raise TransportUnavailableError("UDP transport is not connected")
        self._socket.settimeout(timeout_sec)
        try:
            data, _ = self._socket.recvfrom(4096)
            return data
        except socket.timeout:
            return None
        except OSError as exc:
            raise TemporaryNetworkError(f"UDP receive failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_address(self) -> tuple[str, int]:
        """Resolve *self._host* to an IPv4 address.

        Raises:
            DnsResolutionError: If the hostname cannot be resolved.
        """
        try:
            addr_info = socket.getaddrinfo(
                self._host, self._port, socket.AF_INET, socket.SOCK_DGRAM
            )
            ip = addr_info[0][4][0]
            return (ip, self._port)
        except socket.gaierror as exc:
            raise DnsResolutionError(
                f"DNS resolution failed for '{self._host}': {exc}"
            ) from exc
