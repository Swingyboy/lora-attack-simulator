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

from lorawan_sim.domain.scenario.schema import (
    DeviceConfig,
    LoggingConfig,
)


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


# Type alias for backward compatibility and type hints
AttackScenarioConfig = AttackScenarioV1
