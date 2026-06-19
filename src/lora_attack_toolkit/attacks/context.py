"""Attack execution context for dependency injection."""

from __future__ import annotations

import threading
import warnings
from dataclasses import dataclass, field
from logging import Logger
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.packet_capture import PacketCapture
    from lora_attack_toolkit.config import ExpectedBehavior, RadioMetadata
    from lora_attack_toolkit.runtime.device import SimulatedDevice
    from lora_attack_toolkit.runtime.gateway import GatewaySimulator


@dataclass(frozen=True)
class AttackServices:
    """Immutable service dependencies.

    Provides access to core simulator services that attacks need:
    - Device simulator
    - Gateway simulator
    - Logger
    - Packet capture
    - Optional metrics collector
    """

    device: SimulatedDevice
    gateway: GatewaySimulator
    logger: Logger
    capture: PacketCapture
    metrics: Any | None = None  # MetricsCollector when implemented


@dataclass(frozen=True)
class AttackInput:
    """Immutable scenario inputs.

    Contains all configuration and expectations for an attack:
    - Typed attack-specific configuration (preferred)
    - Expected behavior / security criteria
    - Radio metadata for transmissions
    - Timeout for execution

    The typed_config field should hold one of:
    - ReplayConfigV1 (for uplink replay attacks)
    - JoinDevNonceConfigV1 (for join devnonce attacks)
    - MACCommandConfigV1 (for MAC command attacks)
    - Any custom typed config for custom attacks

    Using typed configs instead of raw dicts provides:
    - Type safety and IDE support
    - Validation at parse time
    - Clear contract for what each attack needs
    """

    # Typed attack configuration (from lora_attack_toolkit.config parsers)
    typed_config: Any  # ReplayConfigV1, JoinDevNonceConfigV1, etc

    # Expected behavior / security criteria
    expected_behavior: ExpectedBehavior | None

    # Radio metadata for transmissions
    radio: RadioMetadata

    # Execution timeout
    timeout_sec: float

    # Legacy: raw dict config for backwards compatibility
    # New code should use typed_config instead
    attack_config: dict[str, Any] | None = None


@dataclass
class AttackContext:
    """Complete attack execution context.

    Combines services, inputs, and mutable state for attack execution.

    This is the dependency injection container passed to attacks,
    providing everything they need without tight coupling to framework internals.

    This is the ONLY interface exposed to attack plugins.

    Usage:
        ctx = AttackContext(
            services=AttackServices(device, gateway, logger, capture),
            input=AttackInput(config, expected, radio, timeout),
        )
        result = attack.run(ctx)
    """

    services: AttackServices
    input: AttackInput
    state: dict[str, Any] = field(default_factory=dict)
    cancel_event: threading.Event = field(default_factory=threading.Event)

    # Convenience accessors for common needs
    @property
    def device(self) -> SimulatedDevice:
        """Shortcut to device service."""
        return self.services.device

    @property
    def gateway(self) -> GatewaySimulator:
        """Shortcut to gateway service."""
        return self.services.gateway

    @property
    def logger(self) -> Logger:
        """Shortcut to logger service."""
        return self.services.logger

    @property
    def capture(self) -> PacketCapture:
        """Shortcut to packet capture service."""
        return self.services.capture

    @property
    def metrics(self) -> Any | None:
        """Shortcut to metrics collector (if available)."""
        return self.services.metrics

    @property
    def config(self) -> Any:
        """
        Shortcut to typed attack config (preferred).

        Returns the typed config object (ReplayConfigV1, JoinDevNonceConfigV1, etc).
        Falls back to the legacy raw-dict ``attack_config`` when ``typed_config`` is
        ``None``, emitting a :class:`DeprecationWarning` to guide callers toward the
        typed path.
        """
        if self.input.typed_config is not None:
            return self.input.typed_config
        warnings.warn(
            "ctx.config is returning a raw dict via the legacy attack_config field. "
            "Migrate to typed_config (e.g. UplinkReplayConfigV1) for type safety.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.input.attack_config

    @property
    def expected(self) -> ExpectedBehavior | None:
        """Shortcut to expected behavior."""
        return self.input.expected_behavior

    @property
    def radio(self) -> RadioMetadata:
        """Shortcut to radio metadata."""
        return self.input.radio

    @property
    def timeout(self) -> float:
        """Shortcut to execution timeout."""
        return self.input.timeout_sec
