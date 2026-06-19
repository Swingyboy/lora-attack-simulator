"""Tests for gateway_lifecycle context manager and interruptible_sleep."""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, call

import pytest

from lora_attack_toolkit.attacks.lifecycle import gateway_lifecycle
from lora_attack_toolkit.lorawan.time_utils import interruptible_sleep


# ── interruptible_sleep ───────────────────────────────────────────────────────


class TestInterruptibleSleep:
    def test_sleeps_full_duration_without_cancel(self) -> None:
        t0 = time.monotonic()
        result = interruptible_sleep(0.1)
        elapsed = time.monotonic() - t0
        assert result is True
        assert elapsed >= 0.09

    def test_returns_false_when_already_cancelled(self) -> None:
        evt = threading.Event()
        evt.set()
        result = interruptible_sleep(10.0, evt)
        assert result is False

    def test_wakes_early_on_cancel(self) -> None:
        evt = threading.Event()

        def _set_later() -> None:
            time.sleep(0.03)
            evt.set()

        threading.Thread(target=_set_later, daemon=True).start()

        t0 = time.monotonic()
        result = interruptible_sleep(10.0, evt, poll_interval_sec=0.01)
        elapsed = time.monotonic() - t0

        assert result is False
        assert elapsed < 1.0  # Should wake well under 1 second

    def test_zero_duration_not_cancelled(self) -> None:
        evt = threading.Event()
        assert interruptible_sleep(0.0, evt) is True

    def test_negative_duration_not_cancelled(self) -> None:
        evt = threading.Event()
        assert interruptible_sleep(-1.0, evt) is True

    def test_no_cancel_event_behaves_like_sleep(self) -> None:
        t0 = time.monotonic()
        result = interruptible_sleep(0.05, None)
        elapsed = time.monotonic() - t0
        assert result is True
        assert elapsed >= 0.04


# ── gateway_lifecycle ─────────────────────────────────────────────────────────


class TestGatewayLifecycle:
    def test_starts_and_stops_gateway(self) -> None:
        gw = MagicMock()
        with gateway_lifecycle(gw):
            gw.forward_uplink(b"frame", MagicMock())
        gw.start.assert_called_once()
        gw.stop.assert_called_once()

    def test_stop_called_on_exception(self) -> None:
        gw = MagicMock()
        with pytest.raises(RuntimeError):
            with gateway_lifecycle(gw):
                raise RuntimeError("attack failed")
        gw.start.assert_called_once()
        gw.stop.assert_called_once()

    def test_stop_failure_suppressed(self) -> None:
        gw = MagicMock()
        gw.stop.side_effect = OSError("transport closed")
        # Must not propagate the stop error
        with gateway_lifecycle(gw):
            pass
        gw.stop.assert_called_once()

    def test_stop_failure_does_not_mask_attack_exception(self) -> None:
        gw = MagicMock()
        gw.stop.side_effect = OSError("transport closed")
        with pytest.raises(ValueError, match="attack error"):
            with gateway_lifecycle(gw):
                raise ValueError("attack error")

    def test_start_stop_order(self) -> None:
        order: list[str] = []
        gw = MagicMock()
        gw.start.side_effect = lambda: order.append("start")
        gw.stop.side_effect = lambda: order.append("stop")
        with gateway_lifecycle(gw):
            order.append("body")
        assert order == ["start", "body", "stop"]
