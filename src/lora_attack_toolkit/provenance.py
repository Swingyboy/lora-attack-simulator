"""Reproducibility metadata for saved attack results.

Every persisted result embeds enough provenance to reproduce and audit a run:
toolkit version, Git commit, a hash + snapshot of the effective scenario, the
target Network Server (product/version), region, LoRaWAN version and the
declared evaluation profile, the behaviour under test, the full effective
configuration, timing, evidence references, the verdict with its confidence and
rationale, the control-probe outcome, and the prototype's known limitations.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import subprocess
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.result import AttackResult
    from lora_attack_toolkit.config import AttackScenarioV1

UNKNOWN = "unknown"

# Deliberate prototype trade-offs recorded on every result so downstream
# analysis never over-reads the verdicts (see AGENTS.md "Known Limitations").
KNOWN_LIMITATIONS: tuple[str, ...] = (
    "Transport limited to Semtech UDP; MQTT/WebSocket not implemented.",
    "Single region (EU868) and LoRaWAN Class A / OTAA only.",
    "Timing is simulated, not guaranteed accurate to the millisecond.",
    "Not a full LoRaWAN conformance suite; verdicts are per-attack only.",
)


def toolkit_version() -> str:
    """Return the toolkit version (single source: package ``__version__``)."""
    from lora_attack_toolkit import __version__

    return __version__


def git_commit() -> str:
    """Return the current Git commit SHA, or ``"unknown"`` outside a repo."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return UNKNOWN
    if out.returncode != 0:
        return UNKNOWN
    sha = out.stdout.strip()
    return sha or UNKNOWN


def _scenario_snapshot(scenario: AttackScenarioV1) -> dict[str, Any]:
    """Return a JSON-serializable snapshot of the full effective scenario.

    Secret material under ``device.activation`` (AppKey, NwkKey, session keys)
    is redacted: the raw value is replaced with ``"<redacted>"`` and a
    non-reversible SHA-256 fingerprint is stored alongside it so two runs of
    the *same* scenario can be compared without exposing the key.
    """
    snap = dataclasses.asdict(scenario)
    act: dict[str, Any] = snap.get("device", {}).get("activation", {})
    _SECRET_KEYS = ("app_key", "nwk_key", "app_s_key", "nwk_s_key")
    for key in _SECRET_KEYS:
        raw = act.get(key)
        if raw:
            try:
                fingerprint = hashlib.sha256(bytes.fromhex(str(raw))).hexdigest()
            except (ValueError, TypeError):
                fingerprint = hashlib.sha256(str(raw).encode()).hexdigest()
            act[f"{key}_sha256"] = fingerprint
            act[key] = "<redacted>"
    return snap


def _canonical_hash(snapshot: dict[str, Any]) -> str:
    """Return a stable SHA-256 hash of *snapshot* (key-order independent)."""
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _extract_control_probe(metrics: dict[str, Any]) -> dict[str, Any]:
    """Pull any ``control_probe*`` keys out of attack metrics."""
    return {k: v for k, v in metrics.items() if k.startswith("control_probe")}


def build_reproducibility(
    scenario: AttackScenarioV1,
    result: AttackResult,
    *,
    started_at: str,
    ended_at: str,
    duration_sec: float,
) -> dict[str, Any]:
    """Build the reproducibility metadata block for a finished attack run.

    Args:
        scenario: The fully-parsed scenario that was executed.
        result: The :class:`AttackResult` produced by the attack.
        started_at: ISO-8601 timestamp captured before ``attack.run``.
        ended_at: ISO-8601 timestamp captured after ``attack.run``.
        duration_sec: Wall-clock execution duration in seconds.

    Returns:
        A JSON-serializable dict with every reproducibility field populated.
    """
    snapshot = _scenario_snapshot(scenario)
    metrics = result.metrics or {}
    rationale = metrics.get("rationale") or result.validation_summary

    return {
        "toolkit_version": toolkit_version(),
        "git_commit": git_commit(),
        "scenario_hash": _canonical_hash(snapshot),
        "scenario_snapshot": snapshot,
        "effective_config": {
            "attack_type": scenario.attack.type,
            "config": scenario.attack.config,
        },
        "network_server": {
            "name": scenario.target.name,
            "product": scenario.target.server_product,
            "version": scenario.target.server_version,
            "transport": scenario.target.transport,
            "host": scenario.target.host,
            "port": scenario.target.port,
        },
        "region": scenario.gateway.radio.region,
        "lorawan_version": scenario.device.lorawan_version,
        "declared_lorawan_profile": scenario.expected.profile,
        "behavior_under_test": metrics.get("behavior_under_test"),
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_sec": duration_sec,
        "evidence": {
            "captured_packets": result.captured_packets,
        },
        "verdict": result.security_verdict.value,
        "confidence": result.confidence.value,
        "confidence_rationale": rationale,
        "control_probe": _extract_control_probe(metrics),
        "warnings": list(KNOWN_LIMITATIONS),
    }
