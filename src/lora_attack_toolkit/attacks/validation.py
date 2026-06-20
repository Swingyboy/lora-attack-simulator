"""Validation utilities for expected behavior criteria."""

from __future__ import annotations

from typing import Any

# Registry mapping user-facing profile names to internal validation parameters.
# Users specify a profile name in their scenario file; the framework resolves
# the corresponding secure_behavior description and list of security criteria.
VALIDATION_PROFILES: dict[str, dict[str, Any]] = {
    "lorawan_1_0_3_devnonce_validation": {
        "secure_behavior": "ns_remembers_all_historical_devnonces",
        "security_criteria": [
            "first_join_request_is_accepted",
            "replayed_join_requests_with_same_devnonce_are_rejected",
            "ns_maintains_devnonce_history",
        ],
    },
    "lorawan_uplink_replay_protection": {
        "secure_behavior": "ns_rejects_replayed_uplinks_with_same_fcnt",
        "security_criteria": [
            "first_uplink_is_sent",
            "replayed_uplinks_with_same_fcnt_are_rejected",
            "ns_maintains_fcnt_validation",
        ],
    },
    "lorawan_mac_command_validation": {
        "secure_behavior": "ns_validates_mac_commands_and_maintains_secure_adr_state",
        "security_criteria": [
            "ns_validates_mac_command_syntax",
            "ns_maintains_secure_adr_state",
        ],
    },
    "lorawan_uplink_forgery_protection": {
        "secure_behavior": "ns_rejects_forged_uplinks_with_invalid_mic_or_wrong_devaddr",
        "security_criteria": [
            "ns_rejects_uplinks_with_invalid_mic",
            "ns_rejects_uplinks_with_replayed_fcnt",
            "ns_rejects_uplinks_with_wrong_devaddr",
            "ns_accepts_only_authenticated_mac_commands",
        ],
    },
}


class CriterionResult:
    """Result of evaluating a single success criterion."""

    def __init__(self, criterion: str, passed: bool, message: str):
        self.criterion = criterion
        self.passed = passed
        self.message = message

    def to_dict(self) -> dict[str, Any]:
        return {
            "criterion": self.criterion,
            "passed": self.passed,
            "message": self.message,
        }


class ValidationResult:
    """Aggregated validation results for all criteria."""

    def __init__(self, secure_behavior: str):
        self.secure_behavior = secure_behavior
        self.results: list[CriterionResult] = []

    def add_result(self, criterion: str, passed: bool, message: str) -> None:
        """Add a criterion evaluation result."""
        self.results.append(CriterionResult(criterion, passed, message))

    def all_passed(self) -> bool:
        """Check if all criteria passed."""
        return all(r.passed for r in self.results)

    def get_summary(self) -> str:
        """Generate human-readable validation summary."""
        passed_count = sum(1 for r in self.results if r.passed)
        total_count = len(self.results)

        if passed_count == total_count:
            return f"✅ SECURE: All {total_count} criteria passed - {self.secure_behavior}"
        elif passed_count == 0:
            return f"⚠️  VULNERABLE: 0/{total_count} criteria passed - NS behavior deviates from {self.secure_behavior}"
        else:
            return f"⚠️  PARTIALLY SECURE: {passed_count}/{total_count} criteria passed - review findings"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for inclusion in attack results."""
        return {
            "secure_behavior": self.secure_behavior,
            "criteria_met": {r.criterion: r.passed for r in self.results},
            "criteria_details": [r.to_dict() for r in self.results],
            "all_passed": self.all_passed(),
            "summary": self.get_summary(),
        }


# Criterion validators for common patterns


def validate_replay_criterion(
    criterion: str, metrics: dict[str, Any], capture_stats: dict[str, Any]
) -> CriterionResult:
    """
    Validate replay attack criteria.

    Supported criteria:
    - "first_uplink_is_sent" - original uplink was captured
    - "replayed_uplinks_with_same_fcnt_are_rejected" - NS rejected replay
    - "ns_maintains_fcnt_validation" - FCnt validation working
    - "replay_attack_is_blocked" - replay not accepted by NS

    When the enhanced replay path is used, ``metrics["verdict"]`` contains a
    protocol-level verdict derived from RX-window timing and GPS-time correlation
    of DeviceTimeAns responses — see ``_determine_verdict()`` in replay.py.
    When only the legacy path is used, ``verdict`` is absent and the result is
    reported as INCONCLUSIVE rather than emitting a downlink-count heuristic
    that produces systematic false positives.
    """
    if criterion == "first_uplink_is_sent":
        has_original = (
            metrics.get("original_fcnt") is not None or metrics.get("captured_fcnt") is not None
        )
        fcnt = metrics.get("original_fcnt", metrics.get("captured_fcnt"))
        if has_original:
            return CriterionResult(criterion, True, f"Original uplink sent with FCnt={fcnt}")
        return CriterionResult(criterion, False, "No original uplink detected")

    elif criterion in (
        "replayed_uplinks_with_same_fcnt_are_rejected",
        "replay_attack_is_blocked",
        "ns_maintains_fcnt_validation",
    ):
        replays_count = metrics.get("replays_count", metrics.get("replay_count", 0))
        if replays_count == 0:
            return CriterionResult(
                criterion, False, "No replay packets detected - attack did not execute"
            )

        # If a protocol-level verdict is available (enhanced replay path), use it
        # directly — it is based on RX-window timing and GPS-time correlation, not
        # a raw downlink count.
        verdict = metrics.get("verdict")
        if verdict is not None:
            if verdict == "protected":
                return CriterionResult(criterion, True, "NS rejected replay (verdict=protected)")
            elif verdict == "vulnerable":
                return CriterionResult(
                    criterion, False, "⚠️  NS accepted replay (verdict=vulnerable)"
                )
            elif verdict == "possible_vulnerability":
                return CriterionResult(
                    criterion,
                    False,
                    "⚠️  Possible replay acceptance (verdict=possible_vulnerability) — manual review recommended",
                )
            else:
                # inconclusive or unknown verdict value
                return CriterionResult(
                    criterion, False, f"Verdict inconclusive ({verdict!r}) — manual review required"
                )

        # No protocol-level verdict available (legacy path).  Downlink count alone
        # is not a reliable indicator of acceptance; report as not evaluated.
        return CriterionResult(
            criterion,
            False,
            "Criterion not fully evaluated — protocol-level verdict unavailable; manual review required",
        )

    else:
        return CriterionResult(criterion, False, "Criterion not recognized for replay attack")


def validate_join_criterion(
    criterion: str, metrics: dict[str, Any], capture_stats: dict[str, Any]
) -> CriterionResult:
    """
    Validate join abuse attack criteria.

    Supported criteria:
    - "first_join_request_is_accepted" - initial join succeeded
    - "replayed_join_requests_with_same_devnonce_are_rejected" - DevNonce validation working
    - "ns_maintains_devnonce_history" - DevNonce tracking in place
    """
    attack_type = metrics.get("attack_type")

    if criterion == "first_join_request_is_accepted":
        join_accepts = metrics.get(
            "accepted_generation_count", metrics.get("join_accepts_received", 0)
        )
        if join_accepts >= 1:
            return CriterionResult(
                criterion, True, f"Initial join succeeded ({join_accepts} accepted baseline joins)"
            )
        return CriterionResult(criterion, False, "No JoinAccepts received - initial join failed")

    elif criterion in (
        "replayed_join_requests_with_same_devnonce_are_rejected",
        "ns_maintains_devnonce_history",
    ):
        if attack_type == "join_devnonce":
            final_accepted = metrics.get("final_join_accepted", False)
            dev_nonce = metrics.get("final_devnonce", metrics.get("dev_nonce", "unknown"))

            if final_accepted:
                return CriterionResult(
                    criterion,
                    False,
                    f"⚠️  VULNERABLE: NS accepted final DevNonce {dev_nonce}",
                )

            return CriterionResult(criterion, True, f"Final DevNonce {dev_nonce} was rejected")

        return CriterionResult(criterion, False, "Criterion not applicable for this attack mode")

    else:
        return CriterionResult(criterion, False, "Criterion not recognized for join abuse attack")


def validate_mac_criterion(
    criterion: str, metrics: dict[str, Any], capture_stats: dict[str, Any]
) -> CriterionResult:
    """
    Validate MAC command abuse criteria.

    Supported criteria:
    - "ns_validates_mac_command_syntax" - malformed commands rejected
    - "ns_rejects_out_of_spec_parameters" - invalid parameters rejected
    - "ns_ignores_malicious_adr_manipulation" - ADR not manipulated
    - "ns_maintains_secure_adr_state" - ADR state remains secure
    """
    if criterion in ("ns_validates_mac_command_syntax", "ns_rejects_out_of_spec_parameters"):
        malformed_count = metrics.get("malformed_commands_sent", 0)
        invalid_count = metrics.get("invalid_commands_sent", 0)

        # Check if NS acknowledged malformed/invalid commands
        # Secure behavior: NS should ignore or reject them
        adr_state_changes = metrics.get("adr_state_changes", 0)

        if malformed_count > 0 or invalid_count > 0:
            if adr_state_changes > 0:
                return CriterionResult(
                    criterion,
                    False,
                    f"⚠️  NS may have processed {malformed_count + invalid_count} malformed/invalid commands (ADR state changed)",
                )

            return CriterionResult(
                criterion,
                True,
                f"Malformed/invalid commands ({malformed_count + invalid_count}) likely rejected - no ADR state changes",
            )

        return CriterionResult(criterion, True, "No malformed commands sent (attack not executed)")

    elif criterion in ("ns_ignores_malicious_adr_manipulation", "ns_maintains_secure_adr_state"):
        # Check if ADR parameters stayed within secure bounds
        final_data_rate = metrics.get("final_data_rate")
        final_tx_power = metrics.get("final_tx_power")

        if final_data_rate is None or final_tx_power is None:
            return CriterionResult(criterion, False, "ADR state not tracked")

        # LoRaWAN 1.0.3 §2.2.3 defines TX power as an index (0–7) into a
        # region-specific table.  For EU868 index 0 is the highest power
        # (14 dBm) and index 7 is the lowest.  Any value outside 0–7 is
        # out-of-spec and indicates potential manipulation.
        _MAX_TX_POWER_INDEX = 7
        if final_tx_power > _MAX_TX_POWER_INDEX:
            return CriterionResult(
                criterion,
                False,
                f"⚠️  TX power index {final_tx_power} out of spec (valid range 0–{_MAX_TX_POWER_INDEX} for EU868)",
            )

        return CriterionResult(
            criterion,
            True,
            f"ADR state within normal bounds - DR={final_data_rate}, TXPower={final_tx_power}",
        )

    else:
        return CriterionResult(criterion, False, "Criterion not recognized for MAC command abuse")


def validate_criteria(
    attack_type: str,
    criteria: list[str],
    metrics: dict[str, Any],
    capture_stats: dict[str, Any],
    secure_behavior: str,
) -> ValidationResult:
    """
    Validate success criteria against attack results.

    Args:
        attack_type: Type of attack ("uplink_replay", "join_devnonce", "mac_command_injection")
        criteria: List of criterion strings to validate
        metrics: Attack-specific metrics from analyzer
        capture_stats: Packet capture statistics
        secure_behavior: Description of expected secure behavior

    Returns:
        ValidationResult with all criterion evaluations
    """
    result = ValidationResult(secure_behavior)

    for criterion in criteria:
        if attack_type in ("uplink_replay", "replay"):
            criterion_result = validate_replay_criterion(criterion, metrics, capture_stats)
        elif attack_type == "join_devnonce":
            criterion_result = validate_join_criterion(criterion, metrics, capture_stats)
        elif attack_type in ("mac_command_injection", "mac_abuse"):
            criterion_result = validate_mac_criterion(criterion, metrics, capture_stats)
        else:
            criterion_result = CriterionResult(
                criterion, False, f"Unknown attack type: {attack_type}"
            )

        result.add_result(
            criterion_result.criterion, criterion_result.passed, criterion_result.message
        )

    return result
