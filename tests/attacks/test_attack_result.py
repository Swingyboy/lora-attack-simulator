"""Tests for the standardized AttackResult model (P0 §4)."""

from __future__ import annotations

import unittest

from lora_attack_toolkit.attacks.result import (
    AttackResult,
    Confidence,
    ExecutionStatus,
    SecurityVerdict,
)


class TestAttackResultFields(unittest.TestCase):
    """AttackResult carries the standardized P0 fields."""

    def _make_result(self, **kwargs) -> AttackResult:
        defaults = dict(
            attack_name="test_attack",
            attack_type="test",
            message="ok",
        )
        defaults.update(kwargs)
        return AttackResult(**defaults)

    def test_default_execution_status_is_completed(self) -> None:
        r = self._make_result()
        self.assertEqual(r.execution_status, ExecutionStatus.COMPLETED)

    def test_default_security_verdict_is_inconclusive(self) -> None:
        r = self._make_result()
        self.assertEqual(r.security_verdict, SecurityVerdict.INCONCLUSIVE)

    def test_default_confidence_is_low(self) -> None:
        r = self._make_result()
        self.assertEqual(r.confidence, Confidence.LOW)

    def test_target_protected_default_none(self) -> None:
        r = self._make_result()
        self.assertIsNone(r.target_protected)

    def test_set_all_new_fields(self) -> None:
        r = self._make_result(
            execution_status=ExecutionStatus.COMPLETED,
            security_verdict=SecurityVerdict.SECURE,
            confidence=Confidence.HIGH,
            target_protected=True,
        )
        self.assertEqual(r.execution_status, ExecutionStatus.COMPLETED)
        self.assertEqual(r.security_verdict, SecurityVerdict.SECURE)
        self.assertEqual(r.confidence, Confidence.HIGH)
        self.assertTrue(r.target_protected)


class TestAttackResultSuccessCompat(unittest.TestCase):
    """Legacy .success property maps execution_status correctly."""

    def test_completed_maps_to_success_true(self) -> None:
        r = AttackResult(
            attack_name="a",
            attack_type="t",
            message="ok",
            execution_status=ExecutionStatus.COMPLETED,
        )
        self.assertTrue(r.success)

    def test_failed_maps_to_success_false(self) -> None:
        r = AttackResult(
            attack_name="a",
            attack_type="t",
            message="err",
            execution_status=ExecutionStatus.FAILED,
        )
        self.assertFalse(r.success)

    def test_cancelled_maps_to_success_false(self) -> None:
        r = AttackResult(
            attack_name="a",
            attack_type="t",
            message="cancelled",
            execution_status=ExecutionStatus.CANCELLED,
        )
        self.assertFalse(r.success)

    def test_success_setter_overrides_status(self) -> None:
        r = AttackResult(
            attack_name="a",
            attack_type="t",
            message="ok",
            execution_status=ExecutionStatus.COMPLETED,
        )
        r.success = False
        self.assertFalse(r.success)


class TestAttackResultSerialization(unittest.TestCase):
    """to_dict and from_dict round-trip for new fields."""

    def test_to_dict_contains_new_fields(self) -> None:
        r = AttackResult(
            attack_name="uplink_replay",
            attack_type="uplink_replay",
            message="Replay attack complete: verdict=protected",
            execution_status=ExecutionStatus.COMPLETED,
            security_verdict=SecurityVerdict.SECURE,
            confidence=Confidence.HIGH,
            target_protected=True,
            metrics={"verdict": "protected"},
        )
        d = r.to_dict()
        self.assertEqual(d["execution_status"], "completed")
        self.assertEqual(d["security_verdict"], "secure")
        self.assertEqual(d["confidence"], "high")
        self.assertTrue(d["target_protected"])
        # Legacy field still present for backward compat
        self.assertIn("success", d)
        self.assertTrue(d["success"])

    def test_from_dict_roundtrip(self) -> None:
        r = AttackResult(
            attack_name="uplink_forgery",
            attack_type="uplink_forgery",
            message="Forged uplink: Rejected",
            execution_status=ExecutionStatus.COMPLETED,
            security_verdict=SecurityVerdict.SECURE,
            confidence=Confidence.HIGH,
            target_protected=True,
            captured_packets=5,
            metrics={"forgery_mode": "invalid_mic"},
        )
        d = r.to_dict()
        r2 = AttackResult.from_dict(d)
        self.assertEqual(r2.attack_name, r.attack_name)
        self.assertEqual(r2.execution_status, r.execution_status)
        self.assertEqual(r2.security_verdict, r.security_verdict)
        self.assertEqual(r2.confidence, r.confidence)
        self.assertEqual(r2.target_protected, r.target_protected)
        self.assertEqual(r2.captured_packets, r.captured_packets)

    def test_from_dict_legacy_success_field(self) -> None:
        """Legacy JSON with only 'success' field is handled gracefully."""
        data = {
            "attack_name": "old_attack",
            "attack_type": "old",
            "message": "legacy result",
            "success": True,
            "metrics": {},
        }
        r = AttackResult.from_dict(data)
        self.assertTrue(r.success)
        # New fields default to their defaults when absent from JSON
        self.assertEqual(r.execution_status, ExecutionStatus.COMPLETED)

    def test_to_dict_omits_none_target_protected(self) -> None:
        """target_protected=None is omitted from serialization."""
        r = AttackResult(
            attack_name="a",
            attack_type="t",
            message="m",
            target_protected=None,
        )
        d = r.to_dict()
        self.assertNotIn("target_protected", d)

    def test_to_dict_includes_target_protected_when_set(self) -> None:
        r = AttackResult(
            attack_name="a",
            attack_type="t",
            message="m",
            target_protected=False,
        )
        d = r.to_dict()
        self.assertIn("target_protected", d)
        self.assertFalse(d["target_protected"])


class TestAttackResultFailedConstructor(unittest.TestCase):
    """AttackResult.failed() convenience constructor."""

    def test_failed_sets_execution_status(self) -> None:
        r = AttackResult.failed(attack_name="a", attack_type="t", error="connection refused")
        self.assertEqual(r.execution_status, ExecutionStatus.FAILED)

    def test_failed_sets_inconclusive_verdict(self) -> None:
        r = AttackResult.failed(attack_name="a", attack_type="t", error="timeout")
        self.assertEqual(r.security_verdict, SecurityVerdict.INCONCLUSIVE)

    def test_failed_stores_error_field(self) -> None:
        r = AttackResult.failed(attack_name="a", attack_type="t", error="boom")
        self.assertEqual(r.error, "boom")

    def test_failed_success_property_is_false(self) -> None:
        r = AttackResult.failed(attack_name="a", attack_type="t", error="x")
        self.assertFalse(r.success)

    def test_failed_custom_message(self) -> None:
        r = AttackResult.failed(attack_name="a", attack_type="t", error="x", message="Custom error")
        self.assertEqual(r.message, "Custom error")


class TestSecurityVerdictSemantics(unittest.TestCase):
    """Both secure and vulnerable runs have execution_status=completed (P0 §4 spec)."""

    def test_secure_run_completed(self) -> None:
        r = AttackResult(
            attack_name="a",
            attack_type="t",
            message="ok",
            execution_status=ExecutionStatus.COMPLETED,
            security_verdict=SecurityVerdict.SECURE,
        )
        self.assertEqual(r.execution_status, ExecutionStatus.COMPLETED)
        self.assertEqual(r.security_verdict, SecurityVerdict.SECURE)
        self.assertTrue(r.success)

    def test_vulnerable_run_completed(self) -> None:
        r = AttackResult(
            attack_name="a",
            attack_type="t",
            message="vuln",
            execution_status=ExecutionStatus.COMPLETED,
            security_verdict=SecurityVerdict.VULNERABLE,
            target_protected=False,
        )
        self.assertEqual(r.execution_status, ExecutionStatus.COMPLETED)
        self.assertEqual(r.security_verdict, SecurityVerdict.VULNERABLE)
        # execution succeeded even though target is vulnerable
        self.assertTrue(r.success)
        self.assertFalse(r.target_protected)


if __name__ == "__main__":
    unittest.main()
