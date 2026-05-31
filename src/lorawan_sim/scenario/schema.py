from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScenarioMeta:
    name: str
    description: str
    duration_sec: int


@dataclass(frozen=True)
class SemtechUdpConfig:
    host: str
    port: int
    pull_data_interval_sec: int


@dataclass(frozen=True)
class RadioMetadata:
    frequency: int
    data_rate: str
    rssi: int
    snr: float


@dataclass(frozen=True)
class GatewayConfig:
    gateway_eui: str
    semtech_udp: SemtechUdpConfig
    radio_metadata: RadioMetadata


@dataclass(frozen=True)
class ActivationConfig:
    mode: str
    dev_eui: str
    join_eui: str
    app_key: str


@dataclass(frozen=True)
class DeviceConfig:
    name: str
    lorawan_version: str
    region: str
    device_class: str
    activation: ActivationConfig


@dataclass(frozen=True)
class PayloadConfig:
    encoding: str
    value: str


@dataclass(frozen=True)
class UplinkConfig:
    enabled: bool
    interval_sec: int
    count: int
    confirmed: bool
    f_port: int
    payload: PayloadConfig


@dataclass(frozen=True)
class LoggingConfig:
    level: str
    log_phy_payload: bool
    log_semtech_udp: bool


@dataclass(frozen=True)
class ScenarioConfig:
    scenario: ScenarioMeta
    gateway: GatewayConfig
    device: DeviceConfig
    uplink: UplinkConfig
    logging: LoggingConfig
