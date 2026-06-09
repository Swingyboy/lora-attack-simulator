"""
Transport layer — UDP, in-memory, and transport abstractions.

Public API
----------
* :class:`~lora_attack_toolkit.transport.transport.TransportClient` — abstract base
* :class:`~lora_attack_toolkit.transport.udp.UdpTransport` — Semtech UDP transport
* :class:`~lora_attack_toolkit.transport.in_memory.InMemoryTransport` — in-process test transport
* :class:`~lora_attack_toolkit.transport.resilient.ResilientTransport` — retry/recovery wrapper
* :class:`~lora_attack_toolkit.transport.retry.RetryPolicy` — retry configuration
* :mod:`lora_attack_toolkit.transport.errors` — exception hierarchy
"""

from lora_attack_toolkit.transport.errors import (
    ConnectionResetError,
    DnsResolutionError,
    TemporaryNetworkError,
    TransportError,
    TransportPermanentError,
    TransportTemporaryError,
    TransportUnavailableError,
)
from lora_attack_toolkit.transport.in_memory import InMemoryTransport
from lora_attack_toolkit.transport.resilient import ResilientTransport
from lora_attack_toolkit.transport.retry import RetryPolicy
from lora_attack_toolkit.transport.transport import TransportClient
from lora_attack_toolkit.transport.udp import UdpTransport

__all__ = [
    "TransportClient",
    "UdpTransport",
    "InMemoryTransport",
    "ResilientTransport",
    "RetryPolicy",
    "TransportError",
    "TransportTemporaryError",
    "TransportPermanentError",
    "DnsResolutionError",
    "ConnectionResetError",
    "TemporaryNetworkError",
    "TransportUnavailableError",
]
