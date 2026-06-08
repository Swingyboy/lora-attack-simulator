"""Attack scenario schema definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from lora_attack_toolkit.core.base_types import (
    DeviceConfig,
    GatewayConfig,
    LoggingConfig,
    RadioMetadata,
)


@dataclass(frozen=True)
class AttackMeta:
    """Attack scenario metadata."""
    
    name: str
    description: str
    attack_type: str  # "replay", "join_devnonce", "mac_abuse"
    timeout_sec: float = 60.0


@dataclass(frozen=True)
class ReplayConfig:
    """Configuration for replay attack."""
    
    mode: str  # "immediate", "delayed", "burst"
    delay_sec: float = 0.0
    burst_count: int = 1
    burst_interval_sec: float = 0.1


@dataclass(frozen=True)
class MACCommandConfig:
    """Configuration for MAC command abuse attack."""
    
    command_type: str  # "LinkADRReq", "RXParamSetupReq", "NewChannelReq", "DevStatusReq"
    malformed: bool = False
    parameters: dict[str, Any] | None = None


@dataclass(frozen=True)
class AttackScenarioConfig:
    """Complete attack scenario configuration."""
    
    attack: AttackMeta
    gateway: GatewayConfig
    device: DeviceConfig
    logging: LoggingConfig
    
    # Attack-specific configurations (only one should be present)
    replay: ReplayConfig | None = None
    mac_command: MACCommandConfig | None = None
    
    def validate(self) -> None:
        """Validate attack scenario configuration."""
        attack_configs = [
            self.replay is not None,
            self.mac_command is not None,
        ]
        
        if sum(attack_configs) != 1:
            raise ValueError("Exactly one attack configuration must be provided")
        
        # Validate attack type matches config
        if self.attack.attack_type == "replay" and self.replay is None:
            raise ValueError("Replay attack requires replay configuration")
        if self.attack.attack_type == "mac_abuse" and self.mac_command is None:
            raise ValueError("MAC command abuse attack requires mac_command configuration")
