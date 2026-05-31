from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lorawan_sim.domain.scenario.schema import (
    ActivationConfig,
    DeviceConfig,
    GatewayConfig,
    LoggingConfig,
    PayloadConfig,
    RadioMetadata,
    ScenarioConfig,
    ScenarioMeta,
    SemtechUdpConfig,
    UplinkConfig,
)


def _expect_hex(name: str, value: str, size_bytes: int) -> None:
    if len(value) != size_bytes * 2:
        raise ValueError(f"{name} must be {size_bytes * 2} hex chars")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be valid hex") from exc


def _expect_bool(name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be boolean")
    return value


def _expect_int(name: str, value: Any, min_value: int | None = None) -> int:
    if not isinstance(value, int):
        raise ValueError(f"{name} must be integer")
    if min_value is not None and value < min_value:
        raise ValueError(f"{name} must be >= {min_value}")
    return value


def _expect_str(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty string")
    return value


def load_scenario(path: str) -> ScenarioConfig:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"scenario file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc

    try:
        scenario = raw["scenario"]
        gateway = raw["gateway"]
        device = raw["device"]
        uplink = raw["uplink"]
        logging = raw["logging"]
    except KeyError as exc:
        raise ValueError(f"missing required section: {exc.args[0]}") from exc

    gateway_eui = _expect_str("gateway.gateway_eui", gateway["gateway_eui"]).lower()
    _expect_hex("gateway.gateway_eui", gateway_eui, 8)

    activation = device["activation"]
    if activation["mode"] != "OTAA":
        raise ValueError("device.activation.mode must be OTAA")

    if device["device_class"] != "A":
        raise ValueError("device.device_class must be A for MVP")
    if device["lorawan_version"] != "1.0.3":
        raise ValueError("device.lorawan_version must be 1.0.3 for MVP")

    dev_eui = _expect_str("device.activation.dev_eui", activation["dev_eui"]).lower()
    join_eui = _expect_str("device.activation.join_eui", activation["join_eui"]).lower()
    app_key = _expect_str("device.activation.app_key", activation["app_key"]).lower()
    _expect_hex("device.activation.dev_eui", dev_eui, 8)
    _expect_hex("device.activation.join_eui", join_eui, 8)
    _expect_hex("device.activation.app_key", app_key, 16)

    payload = uplink["payload"]
    payload_encoding = _expect_str("uplink.payload.encoding", payload["encoding"]).lower()
    if payload_encoding != "hex":
        raise ValueError("uplink.payload.encoding must be hex for MVP")
    payload_value = _expect_str("uplink.payload.value", payload["value"]).lower()
    bytes.fromhex(payload_value)

    return ScenarioConfig(
        scenario=ScenarioMeta(
            name=_expect_str("scenario.name", scenario["name"]),
            description=_expect_str("scenario.description", scenario["description"]),
            duration_sec=_expect_int("scenario.duration_sec", scenario["duration_sec"], 1),
        ),
        gateway=GatewayConfig(
            gateway_eui=gateway_eui,
            semtech_udp=SemtechUdpConfig(
                host=_expect_str("gateway.semtech_udp.host", gateway["semtech_udp"]["host"]),
                port=_expect_int("gateway.semtech_udp.port", gateway["semtech_udp"]["port"], 1),
                pull_data_interval_sec=_expect_int(
                    "gateway.semtech_udp.pull_data_interval_sec",
                    gateway["semtech_udp"]["pull_data_interval_sec"],
                    1,
                ),
            ),
            radio_metadata=RadioMetadata(
                frequency=_expect_int("gateway.radio_metadata.frequency", gateway["radio_metadata"]["frequency"], 1),
                data_rate=_expect_str("gateway.radio_metadata.data_rate", gateway["radio_metadata"]["data_rate"]),
                rssi=_expect_int("gateway.radio_metadata.rssi", gateway["radio_metadata"]["rssi"]),
                snr=float(gateway["radio_metadata"]["snr"]),
            ),
        ),
        device=DeviceConfig(
            name=_expect_str("device.name", device["name"]),
            lorawan_version=device["lorawan_version"],
            region=_expect_str("device.region", device["region"]),
            device_class=device["device_class"],
            activation=ActivationConfig(mode="OTAA", dev_eui=dev_eui, join_eui=join_eui, app_key=app_key),
        ),
        uplink=UplinkConfig(
            enabled=_expect_bool("uplink.enabled", uplink["enabled"]),
            interval_sec=_expect_int("uplink.interval_sec", uplink["interval_sec"], 1),
            count=_expect_int("uplink.count", uplink["count"], 1),
            confirmed=_expect_bool("uplink.confirmed", uplink["confirmed"]),
            f_port=_expect_int("uplink.f_port", uplink["f_port"], 1),
            payload=PayloadConfig(encoding="hex", value=payload_value),
        ),
        logging=LoggingConfig(
            level=_expect_str("logging.level", logging["level"]).upper(),
            log_phy_payload=_expect_bool("logging.log_phy_payload", logging["log_phy_payload"]),
            log_semtech_udp=_expect_bool("logging.log_semtech_udp", logging["log_semtech_udp"]),
        ),
    )
