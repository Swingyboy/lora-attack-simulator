"""Resilient transport wrapper.

:class:`ResilientTransport` decorates any :class:`TransportClient` with
transparent retry and recovery logic.  Attack code interacts with the normal
``TransportClient`` API; transient infrastructure failures are handled
internally without any changes to the attack implementations.

Retry behaviour
---------------
* ``send()`` and ``connect()`` are retried up to ``RetryPolicy.max_attempts``
  times on :class:`~lora_attack_toolkit.transport.errors.TransportTemporaryError`.
  Between attempts the transport is reconnected and an exponential back-off
  delay is applied.
* ``receive()`` is *not* retried (timeouts are normal; the caller loops).
  A reconnect is attempted once and ``None`` is returned so the caller retries
  on the next tick.
* :class:`~lora_attack_toolkit.transport.errors.TransportPermanentError` is
  never retried — it propagates immediately.
"""

from __future__ import annotations

import logging
import time
from logging import Logger
from typing import Any, Callable

from lora_attack_toolkit.transport.errors import (
    TransportError,
    TransportPermanentError,
    TransportTemporaryError,
)
from lora_attack_toolkit.transport.retry import RetryPolicy
from lora_attack_toolkit.transport.transport import TransportClient


class ResilientTransport(TransportClient):
    """Transparent retry/recovery wrapper for any :class:`TransportClient`.

    Example usage::

        inner = UdpTransport("lorawan-ns.example.com", 1700)
        transport = ResilientTransport(inner, logger=logger)
        transport.connect()   # retried automatically on DNS failure
        transport.send(pkt)   # retried automatically on network blip
    """

    def __init__(
        self,
        inner: TransportClient,
        policy: RetryPolicy | None = None,
        logger: Logger | None = None,
    ) -> None:
        self._inner = inner
        self._policy = policy or RetryPolicy()
        self._logger = logger or logging.getLogger(__name__)
        self._transport_name = type(inner).__name__

    # ------------------------------------------------------------------
    # TransportClient interface
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Connect, retrying on transient failures."""
        self._with_retry(lambda: self._inner.connect())

    def disconnect(self) -> None:
        """Disconnect once (no retry)."""
        self._inner.disconnect()

    def reconnect(self) -> None:
        """Reconnect, retrying on transient failures."""
        self._with_retry(lambda: self._inner.reconnect())

    def send(self, payload: bytes) -> None:
        """Send *payload*, retrying on transient failures."""
        self._with_retry(lambda: self._inner.send(payload))

    def receive(self, timeout_sec: float) -> bytes | None:
        """Receive one packet.

        * Normal receive timeout → returns ``None`` (no retry needed).
        * :class:`~lora_attack_toolkit.transport.errors.TransportTemporaryError`
          → log, attempt one reconnect, return ``None``.  The caller retries
          on its next iteration.
        """
        try:
            return self._inner.receive(timeout_sec)
        except TransportPermanentError:
            raise
        except TransportTemporaryError as exc:
            self._logger.warning(
                "Transport error detected during receive.\n"
                "Transport: %s\nError: %s: %s",
                self._transport_name,
                type(exc).__name__,
                exc,
            )
            self._attempt_reconnect()
            return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _with_retry(self, fn: Callable[[], Any]) -> None:
        """Execute *fn*, retrying up to ``policy.max_attempts`` times.

        Retry schedule (with ``max_attempts=3``)::

            initial call → fail  → log "Transport error detected"
                                 → log "Recovery attempt 1/3"  → sleep → reconnect
            retry 1      → fail  → log "Recovery attempt 2/3"  → sleep → reconnect
            retry 2      → fail  → log "Recovery attempt 3/3"  → sleep → reconnect
            retry 3      → fail  → log "Transport recovery failed"
                                 → raise TransportTemporaryError

        On success after one or more failures::

            retry N      → ok    → log "Transport recovered."
        """
        if not self._policy.enabled:
            fn()
            return

        delay = self._policy.initial_delay_sec
        first_error: TransportTemporaryError | None = None

        for attempt in range(self._policy.max_attempts + 1):
            try:
                fn()
                if first_error is not None:
                    self._logger.info("Transport recovered.")
                return

            except TransportPermanentError:
                raise

            except TransportTemporaryError as exc:
                if first_error is None:
                    first_error = exc
                    self._logger.warning(
                        "Transport error detected.\nTransport: %s\nError: %s: %s",
                        self._transport_name,
                        type(exc).__name__,
                        exc,
                    )

                if attempt < self._policy.max_attempts:
                    recovery_num = attempt + 1
                    self._logger.info(
                        "Recovery attempt %d/%d",
                        recovery_num,
                        self._policy.max_attempts,
                    )
                    time.sleep(delay)
                    delay *= self._policy.backoff_multiplier
                    self._attempt_reconnect()

        self._logger.error(
            "Transport recovery failed after %d attempt(s).",
            self._policy.max_attempts,
        )
        raise first_error  # type: ignore[misc]

    def _attempt_reconnect(self) -> None:
        """Try to reconnect the inner transport; log and continue on failure."""
        try:
            self._inner.reconnect()
        except (OSError, TransportError) as exc:
            self._logger.debug("Reconnect attempt failed: %s", exc)
