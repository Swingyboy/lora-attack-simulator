"""Base schema types shared across scenario formats."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RadioMetadata:
    """Radio metadata for gateway simulator."""
    
    frequency: int
    data_rate: str
    rssi: int
    snr: float


@dataclass(frozen=True)
class SemtechUdpConfig:
    """Semtech UDP protocol configuration."""
    
    host: str
    port: int
    pull_data_interval_sec: int


@dataclass(frozen=True)
class GatewayConfig:
    """Gateway simulator configuration."""
    
    gateway_eui: str
    semtech_udp: SemtechUdpConfig
    radio_metadata: RadioMetadata


@dataclass(frozen=True)
class ActivationConfig:
    """Device activation configuration."""
    
    mode: str  # "OTAA" or "ABP"
    dev_eui: str
    join_eui: str
    app_key: str


@dataclass(frozen=True)
class DeviceConfig:
    """Device simulator configuration."""
    
    name: str
    lorawan_version: str
    region: str
    device_class: str
    activation: ActivationConfig
    duty_cycle_enforcement: bool = True  # Enable/disable EU868 Duty Cycle enforcement


@dataclass(frozen=True)
class LoggingConfig:
    """Logging configuration."""
    
    level: str = "INFO"
    log_phy_payload: bool = False
    log_semtech_udp: bool = False
