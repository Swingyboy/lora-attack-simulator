"""Attack scenario schema v1.0 definitions.

This module defines the v1.0 scenario format with improved structure:
- Unified attack.config nesting (no top-level attack blocks)
- Target abstraction (NS connection separate from gateway)
- Expected behavior section (security validation criteria)
- Consistent naming conventions (snake_case, unit suffixes)
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
    """Scenario metadata and classification."""
    
    id: str  # Unique scenario identifier (e.g., "join-replay-basic")
    title: str  # Human-readable title
    description: str  # Short description
    category: str  # High-level category ("replay", "join_abuse", "mac_abuse")
    type: str  # Specific attack type ("uplink_replay", "join_replay", etc.)
    timeout_sec: float  # Maximum execution time


@dataclass(frozen=True)
class ExpectedBehavior:
    """Expected secure behavior and validation criteria.
    
    Defines what secure Network Server behavior should be.
    Used by analyzers to assess security posture.
    """
    
    secure_behavior: str  # Human-readable description of secure behavior
    success_criteria: list[str]  # List of criteria that must be met


# --- Typed Attack Configuration Classes (Phase 2) ---

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
class JoinReplayConfigV1:
    """Join replay attack configuration (v1.0).
    
    Tests DevNonce replay protection by replaying JoinRequests.
    """
    
    mode: str  # "replay" (simple replay mode)
    replay_count: int  # Number of times to replay
    delay_sec: float  # Delay before replay
    dev_nonce_strategy: str  # "reuse_original", "increment", "random"
    mic_strategy: str  # "valid" (recalculate) or "reuse_original"


@dataclass(frozen=True)
class JoinFloodConfigV1:
    """Join flood attack configuration (v1.0).
    
    Tests join handling capacity by flooding with multiple JoinRequests.
    """
    
    mode: str  # "flood" (flood mode)
    flood_count: int  # Total number of JoinRequests to send
    flood_interval_sec: float  # Interval between requests
    virtual_devices: int  # Number of virtual devices (unique DevEUIs)


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
    
    type: str  # Attack type (e.g., "join_replay", "uplink_replay", "mac_abuse")
    config: dict[str, Any]  # Attack-specific configuration (flexible dict)


@dataclass(frozen=True)
class AttackScenarioV1:
    """Complete attack scenario configuration (v1.0 format).
    
    This is the unified structure for all attack scenarios.
    """
    
    schema_version: str  # Always "1.0" for v1 scenarios
    scenario: ScenarioMeta  # Metadata and classification
    target: TargetConfig  # Network Server connection
    gateway: GatewayConfigV1  # Gateway simulator config
    device: DeviceConfig  # Device config (reuses existing schema)
    attack: AttackConfigV1  # Attack execution config
    expected: ExpectedBehavior  # Security validation criteria
    logging: LoggingConfig  # Logging configuration
    
    def validate(self) -> None:
        """Validate scenario configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        # Validate schema version
        if self.schema_version != "1.0":
            raise ValueError(f"Invalid schema version: {self.schema_version} (expected 1.0)")
        
        # Validate attack type matches category
        valid_types = {
            "replay": ["uplink_replay", "downlink_replay"],
            "join_abuse": ["join_replay", "join_flood"],
            "mac_abuse": ["mac_command_injection", "mac_malformed"],
        }
        
        category = self.scenario.category
        attack_type = self.attack.type
        
        if category in valid_types:
            if attack_type not in valid_types[category]:
                raise ValueError(
                    f"Attack type '{attack_type}' not valid for category '{category}'. "
                    f"Valid types: {valid_types[category]}"
                )
        
        # Validate transport
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


def parse_join_replay_config(config: dict[str, Any]) -> JoinReplayConfigV1:
    """Parse join replay config from dict."""
    return JoinReplayConfigV1(
        mode=config.get("mode", "replay"),
        replay_count=config.get("replay_count", 1),
        delay_sec=config.get("delay_sec", 0.5),
        dev_nonce_strategy=config.get("dev_nonce_strategy", "reuse_original"),
        mic_strategy=config.get("mic_strategy", "valid"),
    )


def parse_join_flood_config(config: dict[str, Any]) -> JoinFloodConfigV1:
    """Parse join flood config from dict."""
    return JoinFloodConfigV1(
        mode=config.get("mode", "flood"),
        flood_count=config.get("flood_count", 10),
        flood_interval_sec=config.get("flood_interval_sec", 0.1),
        virtual_devices=config.get("virtual_devices", 1),
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
