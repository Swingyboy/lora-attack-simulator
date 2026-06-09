"""Scenario configuration: types, schema, and loader.

This module is the single source of truth for:
- Configuration dataclasses (DeviceConfig, GatewayConfig, etc.)
- Attack scenario schema v1.0 dataclasses
- JSON scenario loading and validation

Previously spread across core/base_types.py, core/schema.py,
core/schema_v1.py, and core/loader.py.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# ── Base types ────────────────────────────────────────────────────────────────

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
    duty_cycle_enforcement: bool = True


@dataclass(frozen=True)
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    log_phy_payload: bool = False
    log_semtech_udp: bool = False


# ── Legacy schema types (v0 — kept for internal loader compat) ────────────────

@dataclass(frozen=True)
class AttackMeta:
    """Attack scenario metadata."""
    name: str
    description: str
    attack_type: str
    timeout_sec: float = 60.0


@dataclass(frozen=True)
class ReplayConfig:
    """Configuration for replay attack."""
    mode: str
    delay_sec: float = 0.0
    burst_count: int = 1
    burst_interval_sec: float = 0.1


@dataclass(frozen=True)
class MACCommandConfig:
    """Configuration for MAC command abuse attack."""
    command_type: str
    malformed: bool = False
    parameters: dict[str, Any] | None = None


@dataclass(frozen=True)
class AttackScenarioConfig:
    """Complete attack scenario configuration (legacy v0 format)."""
    attack: AttackMeta
    gateway: GatewayConfig
    device: DeviceConfig
    logging: LoggingConfig
    replay: ReplayConfig | None = None
    mac_command: MACCommandConfig | None = None

    def validate(self) -> None:
        attack_configs = [self.replay is not None, self.mac_command is not None]
        if sum(attack_configs) != 1:
            raise ValueError("Exactly one attack configuration must be provided")
        if self.attack.attack_type == "replay" and self.replay is None:
            raise ValueError("Replay attack requires replay configuration")
        if self.attack.attack_type == "mac_abuse" and self.mac_command is None:
            raise ValueError("MAC command abuse attack requires mac_command configuration")


# ── Schema v1.0 types ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TargetConfig:
    """Network Server target configuration."""
    name: str
    transport: str
    host: str
    port: int


@dataclass(frozen=True)
class RadioConfig:
    """Radio metadata for gateway transmissions."""
    region: str
    frequency_hz: int
    data_rate: str
    rssi: int
    snr: float


@dataclass(frozen=True)
class GatewayConfigV1:
    """Gateway simulator configuration (v1.0)."""
    gateway_eui: str
    pull_data_interval_sec: int
    radio: RadioConfig


@dataclass(frozen=True)
class ScenarioMeta:
    """Scenario execution parameters.

    Only contains parameters that directly influence execution.
    Attack metadata (id, title, category, type) is resolved from the registry.
    """
    description: str = ""
    timeout_sec: float = 30.0


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
    profile: str

    @property
    def secure_behavior(self) -> str:
        from lora_attack_toolkit.attacks.validation import VALIDATION_PROFILES
        prof = VALIDATION_PROFILES.get(self.profile)
        return prof["secure_behavior"] if prof else self.profile

    @property
    def security_criteria(self) -> list[str]:
        from lora_attack_toolkit.attacks.validation import VALIDATION_PROFILES
        prof = VALIDATION_PROFILES.get(self.profile)
        return prof["security_criteria"] if prof else []

    @property
    def success_criteria(self) -> list[str]:
        """Alias for security_criteria (backwards compatibility)."""
        return self.security_criteria


@dataclass(frozen=True)
class AttackTiming:
    """Timing configuration for attacks.

    Only join_accept_timeout_sec is user-configurable.
    RX1/RX2 window parameters follow LoRaWAN 1.0.3 specification defaults
    and are not exposed to users.
    """
    join_accept_timeout_sec: float = 7.0
    rx1_delay_sec: float = 1.0
    rx1_window_sec: float = 1.0
    rx2_delay_sec: float = 2.0
    rx2_window_sec: float = 1.0


@dataclass(frozen=True)
class ReplayPhaseConfig:
    """Replay phase configuration for uplink replay attacks."""
    mode: str
    count: int
    delay_sec: float


@dataclass(frozen=True)
class CapturePhaseConfig:
    """Capture phase configuration for replay attacks."""
    perform_join: bool
    send_baseline_uplink: bool
    payload_hex: str | None = None


@dataclass(frozen=True)
class ReplayConfigV1:
    """Replay attack configuration (v1.0)."""
    capture_phase: CapturePhaseConfig
    replay_phase: ReplayPhaseConfig
    fcnt_strategy: str
    mic_strategy: str


@dataclass(frozen=True)
class JoinDevNonceConfigV1:
    """Unified DevNonce validation configuration."""
    valid_join_count: int = 1
    valid_devnonce_start: int | str = 1
    valid_devnonce_step: int = 1
    valid_devnonce_wrap: bool = False
    final_check: str = "same_as_last"
    result_cache_size: int = 10
    final_devnonce: int | None = None
    devnonce_seed: int | None = None
    timing: AttackTiming | None = None


@dataclass(frozen=True)
class MACCommandConfigV1:
    """MAC command abuse configuration (v1.0)."""
    command_type: str
    malformed: bool
    parameters: dict[str, Any] | None = None
    malformation_type: str | None = None


@dataclass(frozen=True)
class AttackConfigV1:
    """Unified attack configuration (v1.0)."""
    type: str
    config: dict[str, Any]


@dataclass(frozen=True)
class AttackScenarioV1:
    """Complete attack scenario configuration (v1.0 format)."""
    scenario: ScenarioMeta
    target: TargetConfig
    gateway: GatewayConfigV1
    device: DeviceConfig
    attack: AttackConfigV1
    expected: ExpectedBehavior
    logging: LoggingConfig

    def validate(self) -> None:
        supported_transports = ["semtech_udp"]
        if self.target.transport not in supported_transports:
            raise ValueError(
                f"Unsupported transport: {self.target.transport}. "
                f"Supported: {supported_transports}"
            )


# ── Attack-specific config parsers ────────────────────────────────────────────

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
        default = AttackTiming()
        min_timeout = default.rx2_delay_sec + default.rx2_window_sec
        if join_accept_timeout_sec < min_timeout:
            raise ValueError(
                f"timing.join_accept_timeout_sec must be >= {min_timeout} "
                f"(rx2_delay_sec + rx2_window_sec)"
            )
        timing = AttackTiming(join_accept_timeout_sec=join_accept_timeout_sec)

    valid_devnonce_start_raw = config.get("valid_devnonce_start", 1)
    if isinstance(valid_devnonce_start_raw, str):
        if valid_devnonce_start_raw.lower() != "random":
            raise ValueError(
                f"valid_devnonce_start must be an integer or 'random', "
                f"got: {valid_devnonce_start_raw!r}"
            )
        valid_devnonce_start: int | str = "random"
    else:
        valid_devnonce_start = int(valid_devnonce_start_raw)

    return JoinDevNonceConfigV1(
        valid_join_count=int(config.get("valid_join_count", 1)),
        valid_devnonce_start=valid_devnonce_start,
        valid_devnonce_step=int(config.get("valid_devnonce_step", 1)),
        valid_devnonce_wrap=bool(config.get("valid_devnonce_wrap", False)),
        final_check=str(config.get("final_check", "same_as_last")),
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


# ── Scenario loader ───────────────────────────────────────────────────────────

def _expect_str(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty string")
    return value


def _expect_int(name: str, value: Any, min_value: int | None = None) -> int:
    if not isinstance(value, int):
        raise ValueError(f"{name} must be integer")
    if min_value is not None and value < min_value:
        raise ValueError(f"{name} must be >= {min_value}")
    return value


def _expect_bool(name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be boolean")
    return value


def _expect_hex(name: str, value: str, size_bytes: int) -> None:
    if len(value) != size_bytes * 2:
        raise ValueError(f"{name} must be {size_bytes * 2} hex chars")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be valid hex") from exc


def load_attack_scenario(path: str) -> AttackScenarioV1:
    """Load attack scenario from JSON file.

    Accepts the simplified v1.0 format where ``schema_version`` and scenario
    metadata fields (``id``, ``title``, ``category``, ``type``) are optional
    and ignored — the framework resolves them from the attack registry.

    Args:
        path: Path to attack scenario JSON file

    Returns:
        AttackScenarioV1 instance

    Raises:
        ValueError: If scenario is invalid
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"attack scenario file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc

    return _load_v1_format(raw)


def _load_v1_format(raw: dict[str, Any]) -> AttackScenarioV1:
    """Load attack scenario in v1.0 format."""
    try:
        target_data = raw["target"]
        gateway_data = raw["gateway"]
        device_data = raw["device"]
        attack_data = raw["attack"]
        expected_data = raw["expected"]
        logging_data = raw["logging"]
    except KeyError as exc:
        raise ValueError(f"missing required section: {exc.args[0]}") from exc

    scenario_data = raw.get("scenario", {})
    scenario = ScenarioMeta(
        description=scenario_data.get("description", ""),
        timeout_sec=float(scenario_data.get("timeout_sec", 30.0)),
    )

    target = TargetConfig(
        name=_expect_str("target.name", target_data["name"]),
        transport=_expect_str("target.transport", target_data["transport"]),
        host=_expect_str("target.host", target_data["host"]),
        port=_expect_int("target.port", target_data["port"], 1),
    )

    gateway_eui = _expect_str("gateway.gateway_eui", gateway_data["gateway_eui"]).lower()
    _expect_hex("gateway.gateway_eui", gateway_eui, 8)

    radio_data = gateway_data["radio"]
    gateway = GatewayConfigV1(
        gateway_eui=gateway_eui,
        pull_data_interval_sec=_expect_int(
            "gateway.pull_data_interval_sec",
            gateway_data["pull_data_interval_sec"],
            1,
        ),
        radio=RadioConfig(
            region=_expect_str("gateway.radio.region", radio_data["region"]),
            frequency_hz=_expect_int("gateway.radio.frequency_hz", radio_data["frequency_hz"], 1),
            data_rate=_expect_str("gateway.radio.data_rate", radio_data["data_rate"]),
            rssi=_expect_int("gateway.radio.rssi", radio_data["rssi"]),
            snr=float(radio_data["snr"]),
        ),
    )

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
        device_class=_expect_str(
            "device.class",
            device_data.get("class", device_data.get("device_class", "A")),
        ),
        activation=ActivationConfig(mode="OTAA", dev_eui=dev_eui, join_eui=join_eui, app_key=app_key),
        duty_cycle_enforcement=bool(device_data.get("duty_cycle_enforcement", True)),
    )

    attack = AttackConfigV1(
        type=_expect_str("attack.type", attack_data["type"]),
        config=attack_data.get("config", {}),
    )

    if "profile" in expected_data:
        expected = ExpectedBehavior(
            profile=_expect_str("expected.profile", expected_data["profile"]),
        )
    elif "secure_behavior" in expected_data:
        secure_behavior = _expect_str("expected.secure_behavior", expected_data["secure_behavior"])
        security_criteria = expected_data.get(
            "security_criteria",
            expected_data.get("success_criteria", []),
        )
        from lora_attack_toolkit.attacks.validation import VALIDATION_PROFILES
        if secure_behavior not in VALIDATION_PROFILES:
            VALIDATION_PROFILES[secure_behavior] = {
                "secure_behavior": secure_behavior,
                "security_criteria": security_criteria,
            }
        expected = ExpectedBehavior(profile=secure_behavior)
    else:
        raise ValueError(
            "expected section must contain 'profile' "
            "(e.g. \"lorawan_1_0_3_devnonce_validation\")"
        )

    logging_cfg = LoggingConfig(
        level=_expect_str("logging.level", logging_data["level"]).upper(),
        log_phy_payload=_expect_bool(
            "logging.log_phy_payload", logging_data.get("log_phy_payload", True)
        ),
        log_semtech_udp=_expect_bool(
            "logging.log_semtech_udp", logging_data.get("log_semtech_udp", True)
        ),
    )

    scenario_v1 = AttackScenarioV1(
        scenario=scenario,
        target=target,
        gateway=gateway,
        device=device,
        attack=attack,
        expected=expected,
        logging=logging_cfg,
    )
    scenario_v1.validate()
    return scenario_v1
