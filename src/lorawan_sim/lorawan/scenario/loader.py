"""Attack scenario loader.

Supports both v0.9 (legacy) and v1.0 (current) scenario formats.
Version detection based on schema_version field.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lorawan_sim.lorawan.scenario.schema import (
    AttackMeta,
    AttackScenarioConfig,
    JoinAbuseConfig,
    MACCommandConfig,
    ReplayConfig,
)
from lorawan_sim.lorawan.scenario.schema_v1 import (
    AttackConfigV1,
    AttackScenarioV1,
    ExpectedBehavior,
    GatewayConfigV1,
    RadioConfig,
    ScenarioMeta,
    TargetConfig,
)
from lorawan_sim.lorawan.scenario.base_types import (
    ActivationConfig,
    DeviceConfig,
    GatewayConfig,
    LoggingConfig,
    RadioMetadata,
    SemtechUdpConfig,
)


# Validation helper functions
def _expect_str(name: str, value: Any) -> str:
    """Validate that value is a non-empty string."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty string")
    return value


def _expect_int(name: str, value: Any, min_value: int | None = None) -> int:
    """Validate that value is an integer, optionally >= min_value."""
    if not isinstance(value, int):
        raise ValueError(f"{name} must be integer")
    if min_value is not None and value < min_value:
        raise ValueError(f"{name} must be >= {min_value}")
    return value


def _expect_bool(name: str, value: Any) -> bool:
    """Validate that value is a boolean."""
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be boolean")
    return value


def _expect_hex(name: str, value: str, size_bytes: int) -> None:
    """Validate that value is valid hex string of expected size."""
    if len(value) != size_bytes * 2:
        raise ValueError(f"{name} must be {size_bytes * 2} hex chars")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be valid hex") from exc


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


def load_attack_scenario(path: str) -> AttackScenarioV1:
    """
    Load attack scenario from JSON file (v1.0 format only).
    
    Args:
        path: Path to attack scenario JSON file
    
    Returns:
        AttackScenarioV1 instance
    
    Raises:
        ValueError: If scenario is invalid or version unsupported
    
    Note:
        Legacy v0.9 format support removed. All scenarios must use schema_version: "1.0"
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"attack scenario file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    
    # Check schema version
    schema_version = raw.get("schema_version")
    
    if schema_version != "1.0":
        raise ValueError(
            f"Unsupported or missing schema version: {schema_version}. "
            f"Only v1.0 is supported. Legacy v0.9 scenarios must be migrated."
        )
    
    return _load_v1_format(raw)


def _load_v1_format(raw: dict[str, Any]) -> AttackScenarioV1:
    """
    Load attack scenario in v1.0 format.
    
    v1.0 format features:
    - Unified structure with all attack configs under attack.config
    - Target section (NS connection separate from gateway)
    - Expected section (security validation criteria)
    - Consistent naming (snake_case, unit suffixes)
    """
    try:
        scenario_data = raw["scenario"]
        target_data = raw["target"]
        gateway_data = raw["gateway"]
        device_data = raw["device"]
        attack_data = raw["attack"]
        expected_data = raw["expected"]
        logging_data = raw["logging"]
    except KeyError as exc:
        raise ValueError(f"v1.0 format: missing required section: {exc.args[0]}") from exc
    
    # Load scenario metadata
    scenario = ScenarioMeta(
        id=_expect_str("scenario.id", scenario_data["id"]),
        title=_expect_str("scenario.title", scenario_data["title"]),
        description=_expect_str("scenario.description", scenario_data["description"]),
        category=_expect_str("scenario.category", scenario_data["category"]),
        type=_expect_str("scenario.type", scenario_data["type"]),
        timeout_sec=float(scenario_data.get("timeout_sec", 60.0)),
    )
    
    # Load target (Network Server connection)
    target = TargetConfig(
        name=_expect_str("target.name", target_data["name"]),
        transport=_expect_str("target.transport", target_data["transport"]),
        host=_expect_str("target.host", target_data["host"]),
        port=_expect_int("target.port", target_data["port"], 1),
    )
    
    # Load gateway
    gateway_eui = _expect_str("gateway.gateway_eui", gateway_data["gateway_eui"]).lower()
    _expect_hex("gateway.gateway_eui", gateway_eui, 8)
    
    radio_data = gateway_data["radio"]
    gateway = GatewayConfigV1(
        gateway_eui=gateway_eui,
        pull_data_interval_sec=_expect_int(
            "gateway.pull_data_interval_sec",
            gateway_data["pull_data_interval_sec"],
            1
        ),
        radio=RadioConfig(
            region=_expect_str("gateway.radio.region", radio_data["region"]),
            frequency_hz=_expect_int("gateway.radio.frequency_hz", radio_data["frequency_hz"], 1),
            data_rate=_expect_str("gateway.radio.data_rate", radio_data["data_rate"]),
            rssi=_expect_int("gateway.radio.rssi", radio_data["rssi"]),
            snr=float(radio_data["snr"]),
        ),
    )
    
    # Load device (reuse existing parser logic)
    activation = device_data["activation"]
    if activation["mode"] != "OTAA":
        raise ValueError("device.activation.mode must be OTAA")
    
    dev_eui = _expect_str("device.activation.dev_eui", activation["dev_eui"]).lower()
    join_eui = _expect_str("device.activation.join_eui", activation["join_eui"]).lower()
    app_key = _expect_str("device.activation.app_key", activation["app_key"]).lower()
    _expect_hex("device.activation.dev_eui", dev_eui, 8)
    _expect_hex("device.activation.join_eui", join_eui, 8)
    _expect_hex("device.activation.app_key", app_key, 16)
    
    device = DeviceConfig(
        name=_expect_str("device.name", device_data["name"]),
        lorawan_version=_expect_str("device.lorawan_version", device_data["lorawan_version"]),
        region=_expect_str("device.region", device_data["region"]),
        device_class=_expect_str("device.class", device_data.get("class", device_data.get("device_class", "A"))),
        activation=ActivationConfig(mode="OTAA", dev_eui=dev_eui, join_eui=join_eui, app_key=app_key),
    )
    
    # Load attack config (flexible dict, no parsing yet)
    attack = AttackConfigV1(
        type=_expect_str("attack.type", attack_data["type"]),
        config=attack_data.get("config", {}),
    )
    
    # Load expected behavior
    expected = ExpectedBehavior(
        secure_behavior=_expect_str("expected.secure_behavior", expected_data["secure_behavior"]),
        success_criteria=expected_data.get("success_criteria", []),
    )
    
    # Load logging
    logging = LoggingConfig(
        level=_expect_str("logging.level", logging_data["level"]).upper(),
        log_phy_payload=_expect_bool("logging.log_phy_payload", logging_data.get("log_phy_payload", True)),
        log_semtech_udp=_expect_bool("logging.log_semtech_udp", logging_data.get("log_semtech_udp", True)),
    )
    
    scenario_v1 = AttackScenarioV1(
        schema_version="1.0",
        scenario=scenario,
        target=target,
        gateway=gateway,
        device=device,
        attack=attack,
        expected=expected,
        logging=logging,
    )
    
    # Validate
    scenario_v1.validate()
    
    return scenario_v1


