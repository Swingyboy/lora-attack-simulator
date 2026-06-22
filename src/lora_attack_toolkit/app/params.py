"""Centralized parameter metadata registry for CLI autocomplete and help."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ParamMeta:
    path: str
    type_str: str  # "str" | "int" | "float" | "bool" | "enum" | "hex"
    description: str
    default: Any
    allowed_values: list[str] | None = None


REGISTRY: list[ParamMeta] = [
    # ── attack.config (join_devnonce) ─────────────────────────────────
    ParamMeta(
        path="attack.config.final_check",
        type_str="enum",
        description="How the final DevNonce validation request is generated.",
        default="same_as_last",
        allowed_values=[
            "replay_first",
            "same_as_last",
            "lower_than_last",
            "lorawan_1_0_4_monotonic_devnonce",
            "custom",
        ],
    ),
    ParamMeta(
        path="attack.config.valid_join_count",
        type_str="int",
        description="Number of valid JoinRequests to send during the generation phase.",
        default=1,
    ),
    ParamMeta(
        path="attack.config.valid_devnonce_start",
        type_str="int|random",
        description='Starting DevNonce value, or "random" for a random 16-bit start.',
        default=1,
        allowed_values=["random"],
    ),
    ParamMeta(
        path="attack.config.valid_devnonce_step",
        type_str="int",
        description="Step between consecutive generated DevNonce values.",
        default=1,
    ),
    ParamMeta(
        path="attack.config.valid_devnonce_wrap",
        type_str="bool",
        description="Wrap DevNonce values at 0xFFFF instead of raising an error.",
        default=False,
        allowed_values=["true", "false"],
    ),
    ParamMeta(
        path="attack.config.devnonce_seed",
        type_str="int",
        description="Seed for reproducible random DevNonce start (requires valid_devnonce_start=random).",
        default=None,
    ),
    ParamMeta(
        path="attack.config.result_cache_size",
        type_str="int",
        description="Maximum number of recent accepted DevNonces kept in memory.",
        default=10,
    ),
    ParamMeta(
        path="attack.config.final_devnonce",
        type_str="int",
        description="Custom DevNonce for the final check (requires final_check=custom).",
        default=None,
    ),
    # ── attack.config.timing ─────────────────────────────────────────
    ParamMeta(
        path="attack.config.timing.join_accept_timeout_sec",
        type_str="float",
        description=(
            "How long (seconds) to wait for a JoinAccept before considering the "
            "join attempt failed.  Must be >= 3.0 (RX2 window close time)."
        ),
        default=7.0,
    ),
    # ── expected ──────────────────────────────────────────────────────
    ParamMeta(
        path="expected.profile",
        type_str="str",
        description=(
            "Validation profile name used to assess NS security posture. "
            "Built-in profiles: lorawan_1_0_3_devnonce_validation, "
            "lorawan_uplink_replay_protection, lorawan_uplink_forgery_protection."
        ),
        default=None,
        allowed_values=[
            "lorawan_1_0_3_devnonce_validation",
            "lorawan_uplink_replay_protection",
            "lorawan_uplink_forgery_protection",
        ],
    ),
    # ── device ───────────────────────────────────────────────────────
    ParamMeta(
        path="device.activation.dev_eui",
        type_str="hex",
        description="Device EUI (16 hex chars).",
        default=None,
    ),
    ParamMeta(
        path="device.activation.join_eui",
        type_str="hex",
        description="Join/App EUI (16 hex chars).",
        default=None,
    ),
    ParamMeta(
        path="device.activation.app_key",
        type_str="hex",
        description="AppKey used for OTAA (32 hex chars).",
        default=None,
    ),
    ParamMeta(
        path="device.activation.mode",
        type_str="enum",
        description="Device activation mode.",
        default="otaa",
        allowed_values=["otaa", "abp"],
    ),
    ParamMeta(
        path="device.lorawan_version",
        type_str="enum",
        description="LoRaWAN specification version.",
        default="1.0.3",
        allowed_values=["1.0.3", "1.1"],
    ),
    ParamMeta(
        path="device.region",
        type_str="str",
        description="LoRaWAN regional parameters (e.g. EU868, US915).",
        default="EU868",
    ),
    # ── gateway ───────────────────────────────────────────────────────
    ParamMeta(
        path="gateway.gateway_eui",
        type_str="hex",
        description="Gateway EUI (16 hex chars).",
        default=None,
    ),
    ParamMeta(
        path="gateway.radio.frequency_hz",
        type_str="int",
        description="Uplink frequency in Hz (e.g. 868100000).",
        default=868100000,
    ),
    ParamMeta(
        path="gateway.radio.data_rate",
        type_str="str",
        description="LoRa data rate string (e.g. SF7BW125).",
        default="SF7BW125",
    ),
    ParamMeta(
        path="gateway.radio.region",
        type_str="str",
        description="Radio region (e.g. EU868).",
        default="EU868",
    ),
    # ── target ───────────────────────────────────────────────────────
    ParamMeta(
        path="target.host",
        type_str="str",
        description="Network Server hostname or IP address.",
        default="127.0.0.1",
    ),
    ParamMeta(
        path="target.port",
        type_str="int",
        description="Network Server UDP port.",
        default=1700,
    ),
    ParamMeta(
        path="target.transport",
        type_str="enum",
        description="Transport protocol.",
        default="semtech_udp",
        allowed_values=["semtech_udp"],
    ),
    # ── scenario ─────────────────────────────────────────────────────
    ParamMeta(
        path="scenario.timeout_sec",
        type_str="float",
        description="Maximum execution time for the attack scenario in seconds.",
        default=300.0,
    ),
    # ── logging (CLI-level) ──────────────────────────────────────────
    ParamMeta(
        path="logging.level",
        type_str="enum",
        description="Active log level for the current session.",
        default="INFO",
        allowed_values=["trace", "debug", "info", "warning", "error"],
    ),
    ParamMeta(
        path="logging.log_phy_payload",
        type_str="bool",
        description="Log raw PHY payload bytes.",
        default=False,
        allowed_values=["true", "false"],
    ),
    ParamMeta(
        path="logging.log_semtech_udp",
        type_str="bool",
        description="Log Semtech UDP packet details.",
        default=False,
        allowed_values=["true", "false"],
    ),
    # ── output (CLI-level) ───────────────────────────────────────────
    ParamMeta(
        path="output.metrics",
        type_str="enum",
        description="Controls how much of the metrics block is shown after an attack.",
        default="summary",
        allowed_values=["none", "summary", "full"],
    ),
]

_BY_PATH: dict[str, ParamMeta] = {p.path: p for p in REGISTRY}


def get_param(path: str) -> ParamMeta | None:
    """Return metadata for a parameter path, or None if not in registry."""
    return _BY_PATH.get(path)


def all_paths() -> list[str]:
    """Return all registered parameter paths."""
    return list(_BY_PATH)


def get_allowed_values(path: str) -> list[str]:
    """Return allowed values for a parameter, or an empty list."""
    meta = _BY_PATH.get(path)
    return meta.allowed_values if meta and meta.allowed_values else []
