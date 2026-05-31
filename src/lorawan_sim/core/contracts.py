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
