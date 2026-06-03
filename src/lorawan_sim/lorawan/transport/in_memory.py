from __future__ import annotations

from collections import deque

from transport.transport import TransportClient


class InMemoryTransport(TransportClient):
    def __init__(self) -> None:
        self.sent_packets: list[bytes] = []
        self._incoming: deque[bytes] = deque()
        self._connected = False

    def connect(self) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def send(self, payload: bytes) -> None:
        if not self._connected:
            raise RuntimeError("transport not connected")
        self.sent_packets.append(payload)

    def receive(self, timeout_sec: float) -> bytes | None:
        if not self._connected:
            raise RuntimeError("transport not connected")
        if not self._incoming:
            return None
        return self._incoming.popleft()

    def queue_incoming(self, payload: bytes) -> None:
        self._incoming.append(payload)
