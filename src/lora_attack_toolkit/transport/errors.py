"""Transport exception hierarchy.

Exceptions are split into two categories:

* :class:`TransportTemporaryError` — transient infrastructure failures that
  are safe to retry (DNS hiccup, short network outage, socket reset, broker
  restart, …).

* :class:`TransportPermanentError` — unrecoverable failures that must be
  reported immediately without retries (invalid configuration, authentication
  failure, unsupported transport, …).

Attack implementations must never catch these exceptions directly.
The :class:`~lora_attack_toolkit.transport.resilient.ResilientTransport`
wrapper handles retry/recovery transparently.
"""

from __future__ import annotations


class TransportError(Exception):
    """Base class for all transport-layer errors."""


class TransportTemporaryError(TransportError):
    """Transient infrastructure failure — the operation may succeed on retry."""


class DnsResolutionError(TransportTemporaryError):
    """Hostname could not be resolved (e.g., ``[Errno -5] No address associated
    with hostname``).  Typically caused by temporary DNS unavailability."""


class ConnectionResetError(TransportTemporaryError):  # noqa: A001
    """An established connection was reset by the remote peer."""


class TemporaryNetworkError(TransportTemporaryError):
    """Generic transient network failure (e.g., ``EHOSTUNREACH``, ``ENETDOWN``,
    ``ECONNREFUSED`` in a context where retrying is appropriate)."""


class TransportUnavailableError(TransportTemporaryError):
    """Transport is temporarily unavailable — e.g., the socket was closed due
    to a previous error, or an MQTT broker has gone offline momentarily."""


class TransportPermanentError(TransportError):
    """Unrecoverable failure — do not retry.

    Examples: invalid host/port configuration, authentication failure,
    unsupported transport type, malformed endpoint URL, TLS certificate error.
    """
