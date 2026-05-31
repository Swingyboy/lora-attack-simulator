from __future__ import annotations

import socket

from lorawan_sim.core.contracts.transport import TransportClient


class UdpTransport(TransportClient):
    def __init__(self, host: str, port: int) -> None:
        self._server = (host, port)
        self._socket: socket.socket | None = None

    def connect(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.1)
        self._socket = sock

    def disconnect(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def send(self, payload: bytes) -> None:
        if self._socket is None:
            raise RuntimeError("transport not connected")
        self._socket.sendto(payload, self._server)

    def receive(self, timeout_sec: float) -> bytes | None:
        if self._socket is None:
            raise RuntimeError("transport not connected")
        self._socket.settimeout(timeout_sec)
        try:
            data, _ = self._socket.recvfrom(4096)
        except socket.timeout:
            return None
        return data
