"""Attack lifecycle helpers.

Provides :class:`GatewayLifecycle` — a context manager that guarantees
gateway start/stop even when an attack raises an exception or is cancelled.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import TYPE_CHECKING, Generator

if TYPE_CHECKING:
    from lora_attack_toolkit.runtime.gateway import GatewaySimulator

_logger = logging.getLogger(__name__)


@contextmanager
def gateway_lifecycle(gateway: "GatewaySimulator") -> Generator[None, None, None]:
    """Start *gateway* on entry and stop it on exit (success, exception, or cancellation).

    Example::

        with gateway_lifecycle(ctx.gateway):
            ctx.gateway.forward_uplink(frame, radio)
            ...

    Any exception raised while stopping the gateway is logged and suppressed
    so that the original exception (if any) propagates cleanly.
    """
    gateway.start()
    try:
        yield
    finally:
        try:
            gateway.stop()
        except Exception as exc:  # noqa: BLE001
            _logger.warning("gateway_lifecycle: stop failed: %s", exc)
