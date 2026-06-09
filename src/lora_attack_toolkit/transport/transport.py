from __future__ import annotations

from abc import ABC, abstractmethod


class TransportClient(ABC):
    @abstractmethod
    def connect(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def disconnect(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def send(self, payload: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    def receive(self, timeout_sec: float) -> bytes | None:
        raise NotImplementedError

    def reconnect(self) -> None:
        """Reconnect the transport.

        Default implementation: disconnect then connect.  Transport
        implementations may override this to perform additional steps such as
        re-subscribing to MQTT topics or restoring WebSocket channel state.
        """
        self.disconnect()
        self.connect()
