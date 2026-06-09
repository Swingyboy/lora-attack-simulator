"""Attack scenario schema v1.0 definitions.

This module defines the v1.0 scenario format with a user-facing simplified structure:
- Scenario section contains only execution-relevant parameters (timeout_sec)
- Attack metadata (id, title, category) is resolved internally from the registry
- Expected behavior is expressed as a named validation profile
- Protocol timing details (RX1/RX2 windows) are internal constants
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Base types imported from base module


@dataclass(frozen=True)
class TargetConfig:
    """Network Server target configuration.
    
    Defines connection to the Network Server under test.
    Separates transport concerns from gateway simulation.
    """
    
    name: str  # Human-readable name (e.g., "chirpstack-local")
    transport: str  # Transport type ("semtech_udp", future: "mqtt", "websocket")
    host: str  # NS hostname or IP
    port: int  # NS port


@dataclass(frozen=True)
class RadioConfig:
    """Radio metadata for gateway transmissions."""
    
    region: str  # LoRaWAN region (e.g., "EU868", "US915")
    frequency_hz: int  # Frequency in Hz (with unit suffix)
    data_rate: str  # Data rate (e.g., "SF7BW125")
    rssi: int  # RSSI in dBm
    snr: float  # SNR in dB


@dataclass(frozen=True)
class GatewayConfigV1:
    """Gateway simulator configuration (v1.0).
    
    Focuses on gateway behavior, not transport (transport is in TargetConfig).
    """
    
    gateway_eui: str  # Gateway EUI (hex, no 0x prefix)
    pull_data_interval_sec: int  # PULL_DATA interval in seconds
    radio: RadioConfig  # Radio metadata


@dataclass(frozen=True)
class ScenarioMeta:
    """Scenario execution parameters.

    Only contains parameters that directly influence execution.
    Attack metadata (id, title, category, type) is resolved from the registry.
    """

    description: str = ""  # Human-readable description (optional, informational only)
    timeout_sec: float = 30.0  # Inter-message pacing interval in seconds


@dataclass(frozen=True)
class ExpectedBehavior:
    """Expected security validation profile.

    Users specify a named profile; the framework resolves it to detailed
    validation criteria internally.

    Example profiles:
    - "lorawan_1_0_3_devnonce_validation"
    - "lorawan_uplink_replay_protection"
    - "lorawan_mac_command_validation"
    """

    profile: str  # Validation profile name

    @property
    def secure_behavior(self) -> str:
        """Resolve the secure behavior description from the profile registry."""
        from lora_attack_toolkit.attacks.validation import VALIDATION_PROFILES
        prof = VALIDATION_PROFILES.get(self.profile)
        return prof["secure_behavior"] if prof else self.profile

    @property
    def security_criteria(self) -> list[str]:
        """Resolve the security criteria list from the profile registry."""
        from lora_attack_toolkit.attacks.validation import VALIDATION_PROFILES
        prof = VALIDATION_PROFILES.get(self.profile)
        return prof["security_criteria"] if prof else []

    @property
    def success_criteria(self) -> list[str]:
        """Alias for security_criteria (backwards compatibility)."""
        return self.security_criteria


# --- Typed Attack Configuration Classes ---

@dataclass(frozen=True)
class AttackTiming:
    """Timing configuration for attacks.

    Only join_accept_timeout_sec is user-configurable.
    RX1/RX2 window parameters follow LoRaWAN 1.0.3 specification defaults
    and are not exposed to users.
    """

    join_accept_timeout_sec: float = 7.0  # Max wait for JoinAccept response

    # Internal protocol constants (LoRaWAN 1.0.3 specification defaults)
    # These are not user-configurable; they are derived from the regional profile.
    rx1_delay_sec: float = 1.0    # LoRaWAN RX1 window delay
    rx1_window_sec: float = 1.0   # LoRaWAN RX1 window duration
    rx2_delay_sec: float = 2.0    # LoRaWAN RX2 window delay (total from uplink)
    rx2_window_sec: float = 1.0   # LoRaWAN RX2 window duration


@dataclass(frozen=True)
class ReplayPhaseConfig:
    """Replay phase configuration for uplink replay attacks."""
    
    mode: str  # "immediate", "delayed", or "burst"
    count: int  # Number of times to replay
    delay_sec: float  # Delay before/between replays


@dataclass(frozen=True)
class CapturePhaseConfig:
    """Capture phase configuration for replay attacks."""
    
    perform_join: bool  # Whether to perform OTAA join
    send_baseline_uplink: bool  # Whether to send initial uplink
    payload_hex: str | None = None  # Optional payload (hex)


@dataclass(frozen=True)
class ReplayConfigV1:
    """Replay attack configuration (v1.0).
    
    For uplink replay attacks - capture legitimate traffic and replay it.
    """
    
    capture_phase: CapturePhaseConfig
    replay_phase: ReplayPhaseConfig
    fcnt_strategy: str  # "reuse_original", "increment", "random"
    mic_strategy: str  # "reuse_original", "recalculate", "corrupt"


@dataclass(frozen=True)
class JoinDevNonceConfigV1:
    """Unified DevNonce validation configuration."""

    valid_join_count: int = 1
    valid_devnonce_start: int | str = 1  # integer or "random"
    valid_devnonce_step: int = 1
    valid_devnonce_wrap: bool = False
    final_check: str = "same_as_last"
    result_cache_size: int = 10
    final_devnonce: int | None = None
    devnonce_seed: int | None = None
    timing: AttackTiming | None = None


@dataclass(frozen=True)
class MACCommandConfigV1:
    """MAC command abuse configuration (v1.0).
    
    Tests MAC command handling by injecting legitimate or malformed commands.
    """
    
    command_type: str  # "LinkADRReq", "RXParamSetupReq", etc.
    malformed: bool  # Whether to generate malformed commands
    parameters: dict[str, Any] | None = None  # Command-specific params
    malformation_type: str | None = None  # "truncated", "oversized", "invalid_values", "corrupted"


@dataclass(frozen=True)
class AttackConfigV1:
    """Unified attack configuration (v1.0).
    
    All attack-specific parameters are nested under config dict.
    No attack-specific top-level blocks.
    """
    
    type: str  # Attack type (e.g., "join_devnonce", "uplink_replay", "mac_abuse")
    config: dict[str, Any]  # Attack-specific configuration (flexible dict)


@dataclass(frozen=True)
class AttackScenarioV1:
    """Complete attack scenario configuration (v1.0 format).
    
    This is the unified structure for all attack scenarios.
    Schema version and scenario metadata are not stored here — they are
    resolved internally from the attack registry.
    """
    
    scenario: ScenarioMeta  # Execution parameters (timeout_sec, description)
    target: TargetConfig  # Network Server connection
    gateway: GatewayConfigV1  # Gateway simulator config
    device: DeviceConfig  # Device config (reuses existing schema)
    attack: AttackConfigV1  # Attack execution config
    expected: ExpectedBehavior  # Security validation profile
    logging: LoggingConfig  # Logging configuration
    
    def validate(self) -> None:
        """Validate scenario configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        supported_transports = ["semtech_udp"]
        if self.target.transport not in supported_transports:
            raise ValueError(
                f"Unsupported transport: {self.target.transport}. "
                f"Supported: {supported_transports}"
            )


# --- Helper Functions for Typed Config Parsing ---

def parse_replay_config(config: dict[str, Any]) -> ReplayConfigV1:
    """Parse uplink replay config from dict."""
    capture_data = config.get("capture_phase", {})
    capture = CapturePhaseConfig(
        perform_join=capture_data.get("perform_join", True),
        send_baseline_uplink=capture_data.get("send_baseline_uplink", True),
        payload_hex=capture_data.get("payload_hex"),
    )
    
    replay_data = config.get("replay_phase", {})
    replay = ReplayPhaseConfig(
        mode=replay_data.get("mode", "immediate"),
        count=replay_data.get("count", 1),
        delay_sec=replay_data.get("delay_sec", 0.0),
    )
    
    return ReplayConfigV1(
        capture_phase=capture,
        replay_phase=replay,
        fcnt_strategy=config.get("fcnt_strategy", "reuse_original"),
        mic_strategy=config.get("mic_strategy", "reuse_original"),
    )


def parse_join_devnonce_config(config: dict[str, Any]) -> JoinDevNonceConfigV1:
    """Parse the unified DevNonce validation config from dict.

    Only ``join_accept_timeout_sec`` is user-configurable within the timing
    sub-section.  RX1/RX2 window values are internal protocol constants and
    are silently ignored if present in the input dict.
    """
    timing: AttackTiming | None = None
    if "timing" in config:
        timing_data = config["timing"]
        join_accept_timeout_sec = float(
            timing_data.get("join_accept_timeout_sec", AttackTiming.join_accept_timeout_sec)
        )
        # Validate against the internal RX2 window constants.
        default = AttackTiming()
        min_timeout = default.rx2_delay_sec + default.rx2_window_sec
        if join_accept_timeout_sec < min_timeout:
            raise ValueError(
                f"timing.join_accept_timeout_sec must be >= {min_timeout} "
                f"(rx2_delay_sec + rx2_window_sec)"
            )
        # Build timing with user-provided join_accept_timeout_sec; all other
        # fields use the LoRaWAN 1.0.3 specification defaults.
        timing = AttackTiming(join_accept_timeout_sec=join_accept_timeout_sec)

    valid_join_count = config.get("valid_join_count", 1)

    valid_devnonce_start_raw = config.get("valid_devnonce_start", 1)
    if isinstance(valid_devnonce_start_raw, str):
        if valid_devnonce_start_raw.lower() != "random":
            raise ValueError(
                f"valid_devnonce_start must be an integer or 'random', got: {valid_devnonce_start_raw!r}"
            )
        valid_devnonce_start: int | str = "random"
    else:
        valid_devnonce_start = int(valid_devnonce_start_raw)

    final_check = config.get("final_check", "same_as_last")

    return JoinDevNonceConfigV1(
        valid_join_count=int(valid_join_count),
        valid_devnonce_start=valid_devnonce_start,
        valid_devnonce_step=int(config.get("valid_devnonce_step", 1)),
        valid_devnonce_wrap=bool(config.get("valid_devnonce_wrap", False)),
        final_check=str(final_check),
        result_cache_size=int(config.get("result_cache_size", 10)),
        final_devnonce=config.get("final_devnonce"),
        devnonce_seed=config.get("devnonce_seed"),
        timing=timing,
    )


def parse_mac_command_config(config: dict[str, Any]) -> MACCommandConfigV1:
    """Parse MAC command abuse config from dict."""
    return MACCommandConfigV1(
        command_type=config["command_type"],
        malformed=config.get("malformed", False),
        parameters=config.get("parameters"),
        malformation_type=config.get("malformation_type"),
    )


# Type alias for backward compatibility and type hints
AttackScenarioConfig = AttackScenarioV1
