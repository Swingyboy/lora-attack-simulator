"""Tests for the results header formatting helpers and _display_results output."""

from __future__ import annotations

import io
import sys
import unittest

import pytest

from lora_attack_toolkit.app.console import LoRaWANConsole

pytestmark = pytest.mark.unit


def _console() -> LoRaWANConsole:
    return object.__new__(LoRaWANConsole)


def _capture_display(results: dict) -> str:
    """Run _display_results and return the captured stdout as a string."""
    console = _console()

    class _FakeSession:
        output_metrics = "none"
        scenario_data = None

    console.session = _FakeSession()
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    try:
        console._display_results(results)
    finally:
        sys.stdout = old_stdout
    return buf.getvalue()


# ---------------------------------------------------------------------------
# _format_execution
# ---------------------------------------------------------------------------


class TestFormatExecution(unittest.TestCase):
    def _f(self, status: str | None) -> str:
        return LoRaWANConsole._format_execution(status)

    def test_completed(self) -> None:
        self.assertIn("yes", self._f("completed"))
        self.assertIn("✓", self._f("completed"))

    def test_failed(self) -> None:
        result = self._f("failed")
        self.assertIn("no", result)
        self.assertIn("failed", result)
        self.assertIn("✗", result)

    def test_error(self) -> None:
        result = self._f("error")
        self.assertIn("no", result)
        self.assertIn("error", result)

    def test_cancelled(self) -> None:
        result = self._f("cancelled")
        self.assertIn("no", result)
        self.assertIn("cancelled", result)
        self.assertIn("■", result)

    def test_none(self) -> None:
        result = self._f(None)
        self.assertIn("unknown", result)

    def test_unknown_value(self) -> None:
        result = self._f("something_else")
        self.assertIn("unknown", result)


# ---------------------------------------------------------------------------
# _format_vulnerability
# ---------------------------------------------------------------------------


class TestFormatVulnerability(unittest.TestCase):
    def _f(self, verdict: str | None, confidence: str | None = None) -> str:
        return LoRaWANConsole._format_vulnerability(verdict, confidence)

    def test_vulnerable(self) -> None:
        result = self._f("vulnerable")
        self.assertIn("DETECTED", result)
        self.assertIn("⚠", result)
        self.assertNotIn("NOT", result)

    def test_secure(self) -> None:
        result = self._f("secure")
        self.assertIn("NOT DETECTED", result)
        self.assertIn("✓", result)

    def test_inconclusive(self) -> None:
        result = self._f("inconclusive")
        self.assertIn("INCONCLUSIVE", result)
        self.assertIn("?", result)

    def test_error(self) -> None:
        result = self._f("error")
        self.assertIn("N/A", result)
        self.assertIn("✗", result)

    def test_none_verdict(self) -> None:
        result = self._f(None)
        self.assertIn("unknown", result)

    def test_unknown_verdict_shows_raw_value(self) -> None:
        result = self._f("some_future_verdict")
        self.assertIn("some_future_verdict", result)

    def test_confidence_appended_when_present(self) -> None:
        result = self._f("vulnerable", "high")
        self.assertIn("DETECTED", result)
        self.assertIn("high", result)
        self.assertIn("confidence", result)

    def test_no_confidence_when_absent(self) -> None:
        result = self._f("secure", None)
        self.assertNotIn("confidence", result)

    def test_confidence_appended_to_inconclusive(self) -> None:
        result = self._f("inconclusive", "medium")
        self.assertIn("INCONCLUSIVE", result)
        self.assertIn("medium", result)


# ---------------------------------------------------------------------------
# _display_results: header section (two-line format)
# ---------------------------------------------------------------------------


class TestDisplayResultsHeader(unittest.TestCase):
    def _display(self, **kwargs) -> str:
        return _capture_display(kwargs)

    def test_completed_vulnerable_shows_both_lines(self) -> None:
        out = self._display(
            execution_status="completed",
            security_verdict="vulnerable",
            confidence="high",
            message="NS accepted lower DevNonce",
        )
        self.assertIn("Attack completed:", out)
        self.assertIn("yes", out)
        self.assertIn("Vulnerability:", out)
        self.assertIn("DETECTED", out)
        # No standalone "SUCCESS" headline that could be mistaken for "secure"
        self.assertNotIn("\nStatus:", out)
        self.assertNotIn("SUCCESS", out)

    def test_completed_secure(self) -> None:
        out = self._display(
            execution_status="completed",
            security_verdict="secure",
            message="NS rejected lower DevNonce",
        )
        self.assertIn("NOT DETECTED", out)
        self.assertNotIn("DETECTED", out.replace("NOT DETECTED", ""))

    def test_completed_inconclusive(self) -> None:
        out = self._display(
            execution_status="completed",
            security_verdict="inconclusive",
            message="Target unreachable",
        )
        self.assertIn("INCONCLUSIVE", out)

    def test_completed_error_verdict(self) -> None:
        out = self._display(
            execution_status="completed",
            security_verdict="error",
            message="Something went wrong",
        )
        self.assertIn("N/A", out)

    def test_failed_execution(self) -> None:
        out = self._display(
            execution_status="failed",
            security_verdict="inconclusive",
            message="Connection refused",
        )
        self.assertIn("Attack completed:", out)
        self.assertIn("no", out)
        self.assertIn("failed", out)
        self.assertIn("Vulnerability:", out)

    def test_cancelled_execution(self) -> None:
        out = self._display(
            execution_status="cancelled",
            security_verdict="inconclusive",
            message="User cancelled",
        )
        self.assertIn("cancelled", out)
        self.assertIn("Vulnerability:", out)

    def test_error_execution(self) -> None:
        out = self._display(
            execution_status="error",
            security_verdict="inconclusive",
            message="Unexpected error",
        )
        self.assertIn("no", out)
        self.assertIn("error", out)

    def test_missing_execution_status_graceful(self) -> None:
        out = self._display(security_verdict="vulnerable", message="m")
        self.assertIn("Attack completed:", out)
        self.assertNotIn("Exception", out)

    def test_missing_security_verdict_graceful(self) -> None:
        out = self._display(execution_status="completed", message="m")
        self.assertIn("Vulnerability:", out)
        self.assertNotIn("Exception", out)

    def test_confidence_shown_in_output(self) -> None:
        out = self._display(
            execution_status="completed",
            security_verdict="vulnerable",
            confidence="high",
            message="m",
        )
        self.assertIn("high", out)
        self.assertIn("confidence", out)

    def test_message_still_shown(self) -> None:
        out = self._display(
            execution_status="completed",
            security_verdict="secure",
            message="The rejections were meaningful",
        )
        self.assertIn("Message:", out)
        self.assertIn("The rejections were meaningful", out)

    def test_two_lines_always_present_regardless_of_status(self) -> None:
        """Both header lines must appear for any combination of status/verdict."""
        for status in ("completed", "failed", "cancelled", "error", None):
            for verdict in ("vulnerable", "secure", "inconclusive", "error", None):
                with self.subTest(status=status, verdict=verdict):
                    out = self._display(
                        execution_status=status,
                        security_verdict=verdict,
                        message="m",
                    )
                    self.assertIn("Attack completed:", out)
                    self.assertIn("Vulnerability:", out)


if __name__ == "__main__":
    unittest.main()
