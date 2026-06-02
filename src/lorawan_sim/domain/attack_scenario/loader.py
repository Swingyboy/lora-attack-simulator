"""Attack scenario loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lorawan_sim.domain.attack_scenario.schema import (
    AttackMeta,
    AttackScenarioConfig,
    JoinAbuseConfig,
    MACCommandConfig,
    ReplayConfig,
)
from lorawan_sim.domain.scenario.loader import (
    _expect_bool,
    _expect_hex,
    _expect_int,
    _expect_str,
)
from lorawan_sim.domain.scenario.schema import (
    ActivationConfig,
    DeviceConfig,
    GatewayConfig,
    LoggingConfig,
    RadioMetadata,
    SemtechUdpConfig,
)


def _load_replay_config(data: dict[str, Any]) -> ReplayConfig:
    """Load replay attack configuration."""
    mode = _expect_str("replay.mode", data["mode"])
    if mode not in ["immediate", "delayed", "burst"]:
        raise ValueError("replay.mode must be immediate, delayed, or burst")
    
    return ReplayConfig(
        mode=mode,
        delay_sec=float(data.get("delay_sec", 0.0)),
        burst_count=_expect_int("replay.burst_count", data.get("burst_count", 1), 1),
        burst_interval_sec=float(data.get("burst_interval_sec", 0.1)),
    )


def _load_join_abuse_config(data: dict[str, Any]) -> JoinAbuseConfig:
    """Load join abuse attack configuration."""
    mode = _expect_str("join_abuse.mode", data["mode"])
    if mode not in ["replay", "flood"]:
        raise ValueError("join_abuse.mode must be replay or flood")
    
    return JoinAbuseConfig(
        mode=mode,
        flood_count=_expect_int("join_abuse.flood_count", data.get("flood_count", 10), 1),
        flood_interval_sec=float(data.get("flood_interval_sec", 0.1)),
        virtual_devices=_expect_int("join_abuse.virtual_devices", data.get("virtual_devices", 1), 1),
    )


def _load_mac_command_config(data: dict[str, Any]) -> MACCommandConfig:
    """Load MAC command abuse configuration."""
    command_type = _expect_str("mac_command.command_type", data["command_type"])
    valid_commands = ["LinkADRReq", "RXParamSetupReq", "NewChannelReq", "DevStatusReq"]
    if command_type not in valid_commands:
        raise ValueError(f"mac_command.command_type must be one of {valid_commands}")
    
    return MACCommandConfig(
        command_type=command_type,
        malformed=_expect_bool("mac_command.malformed", data.get("malformed", False)),
        parameters=data.get("parameters"),
    )


def load_attack_scenario(path: str) -> AttackScenarioConfig:
    """
    Load attack scenario from JSON file.
    
    Args:
        path: Path to attack scenario JSON file
    
    Returns:
        AttackScenarioConfig instance
    
    Raises:
        ValueError: If scenario is invalid
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"attack scenario file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    
    try:
        attack = raw["attack"]
        gateway = raw["gateway"]
        device = raw["device"]
        logging = raw["logging"]
    except KeyError as exc:
        raise ValueError(f"missing required section: {exc.args[0]}") from exc
    
    # Validate gateway
    gateway_eui = _expect_str("gateway.gateway_eui", gateway["gateway_eui"]).lower()
    _expect_hex("gateway.gateway_eui", gateway_eui, 8)
    
    # Validate device activation
    activation = device["activation"]
    if activation["mode"] != "OTAA":
        raise ValueError("device.activation.mode must be OTAA")
    
    dev_eui = _expect_str("device.activation.dev_eui", activation["dev_eui"]).lower()
    join_eui = _expect_str("device.activation.join_eui", activation["join_eui"]).lower()
    app_key = _expect_str("device.activation.app_key", activation["app_key"]).lower()
    _expect_hex("device.activation.dev_eui", dev_eui, 8)
    _expect_hex("device.activation.join_eui", join_eui, 8)
    _expect_hex("device.activation.app_key", app_key, 16)
    
    # Load attack type and config
    attack_type = _expect_str("attack.attack_type", attack["attack_type"])
    if attack_type not in ["replay", "join_abuse", "mac_abuse"]:
        raise ValueError("attack.attack_type must be replay, join_abuse, or mac_abuse")
    
    # Load attack-specific configuration
    replay_config = None
    join_abuse_config = None
    mac_command_config = None
    
    if attack_type == "replay":
        if "replay" not in raw:
            raise ValueError("replay attack requires replay configuration")
        replay_config = _load_replay_config(raw["replay"])
    elif attack_type == "join_abuse":
        if "join_abuse" not in raw:
            raise ValueError("join_abuse attack requires join_abuse configuration")
        join_abuse_config = _load_join_abuse_config(raw["join_abuse"])
    elif attack_type == "mac_abuse":
        if "mac_command" not in raw:
            raise ValueError("mac_abuse attack requires mac_command configuration")
        mac_command_config = _load_mac_command_config(raw["mac_command"])
    
    scenario = AttackScenarioConfig(
        attack=AttackMeta(
            name=_expect_str("attack.name", attack["name"]),
            description=_expect_str("attack.description", attack["description"]),
            attack_type=attack_type,
            timeout_sec=float(attack.get("timeout_sec", 60.0)),
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
            lorawan_version=_expect_str("device.lorawan_version", device["lorawan_version"]),
            region=_expect_str("device.region", device["region"]),
            device_class=_expect_str("device.device_class", device["device_class"]),
            activation=ActivationConfig(mode="OTAA", dev_eui=dev_eui, join_eui=join_eui, app_key=app_key),
        ),
        logging=LoggingConfig(
            level=_expect_str("logging.level", logging["level"]).upper(),
            log_phy_payload=_expect_bool("logging.log_phy_payload", logging.get("log_phy_payload", True)),
            log_semtech_udp=_expect_bool("logging.log_semtech_udp", logging.get("log_semtech_udp", True)),
        ),
        replay=replay_config,
        join_abuse=join_abuse_config,
        mac_command=mac_command_config,
    )
    
    # Validate the complete scenario
    scenario.validate()
    
    return scenario
