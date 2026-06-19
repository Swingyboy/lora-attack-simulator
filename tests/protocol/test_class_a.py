"""Tests for Class A RX1/RX2 receive-window logic."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

import pytest

from lora_attack_toolkit.lorawan.class_a import (
    ClassAReceiver,
    RxWindow,
    RxWindowResult,
    eu868_rx1_data_rate,
)
from lora_attack_toolkit.lorawan.radio import EU868RegionProfile, Radio
from lora_attack_toolkit.lorawan.time_utils import FakeClock


def _make_radio(rx1_dr_offset: int = 0, rx1_delay: float = 1.0) -> Radio:
    r = Radio(EU868RegionProfile(), duty_cycle_enforcement=False)
    r._rx1_dr_offset = rx1_dr_offset
    r._rx1_delay_sec = rx1_delay
    return r


def _make_gateway(*, rx1_frame: bytes | None = None, rx2_frame: bytes | None = None) -> MagicMock:
    """Build a mock gateway that returns *rx1_frame* on the first await_downlink
    and *rx2_frame* on the second (or None for no response)."""
    gw = MagicMock()
    responses = iter([rx1_frame, rx2_frame])
    gw.await_downlink.side_effect = lambda timeout_sec=1.0: next(responses, None)
    return gw


# ── eu868_rx1_data_rate ───────────────────────────────────────────────────────


class TestEu868Rx1DataRate:
    @pytest.mark.parametrize(
        "uplink_dr, offset, expected",
        [
            ("SF7BW125", 0, "SF7BW125"),
            ("SF7BW125", 1, "SF8BW125"),
            ("SF7BW125", 5, "SF12BW125"),
            ("SF12BW125", 0, "SF12BW125"),
            ("SF12BW125", 3, "SF12BW125"),  # clipped at DR0
            ("SF10BW125", 2, "SF12BW125"),
            ("SF8BW125", 1, "SF9BW125"),
        ],
    )
    def test_known_pairs(self, uplink_dr: str, offset: int, expected: str) -> None:
        assert eu868_rx1_data_rate(uplink_dr, offset) == expected

    def test_invalid_dr_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown uplink data-rate"):
            eu868_rx1_data_rate("SF7BW250", 0)

    def test_invalid_offset_raises(self) -> None:
        with pytest.raises(ValueError, match="rx1_dr_offset must be 0–5"):
            eu868_rx1_data_rate("SF7BW125", 6)


# ── ClassAReceiver ────────────────────────────────────────────────────────────


class TestClassAReceiverRx1Success:
    def test_returns_rx1_when_frame_in_rx1(self) -> None:
        radio = _make_radio(rx1_delay=0.0)
        frame = b"\xaa\xbb\xcc"
        gw = _make_gateway(rx1_frame=frame)
        clock = FakeClock(start_mono=0.0)
        receiver = ClassAReceiver(radio, gw, clock=clock, rx_window_sec=0.1)

        result = receiver.await_downlink(
            uplink_freq_hz=868_100_000,
            uplink_dr_str="SF7BW125",
            tx_monotonic=0.0,
        )

        assert result.window == RxWindow.RX1
        assert result.downlink_frame == frame
        assert result.accepted is True

    def test_rx1_freq_and_dr_populated(self) -> None:
        radio = _make_radio(rx1_delay=0.0, rx1_dr_offset=1)
        gw = _make_gateway(rx1_frame=b"\x00")
        clock = FakeClock(start_mono=0.0)
        receiver = ClassAReceiver(radio, gw, clock=clock, rx_window_sec=0.1)

        result = receiver.await_downlink(
            uplink_freq_hz=868_300_000,
            uplink_dr_str="SF7BW125",
            tx_monotonic=0.0,
        )
        assert result.rx1_freq_hz == 868_300_000
        assert result.rx1_data_rate == "SF8BW125"  # offset=1 → DR4


class TestClassAReceiverRx2Fallback:
    def test_returns_rx2_when_rx1_empty(self) -> None:
        radio = _make_radio(rx1_delay=0.0)
        frame = b"\xdd\xee"
        gw = _make_gateway(rx1_frame=None, rx2_frame=frame)
        clock = FakeClock(start_mono=0.0)
        receiver = ClassAReceiver(radio, gw, clock=clock, rx_window_sec=0.0)

        result = receiver.await_downlink(
            uplink_freq_hz=868_100_000,
            uplink_dr_str="SF7BW125",
            tx_monotonic=0.0,
        )

        assert result.window == RxWindow.RX2
        assert result.downlink_frame == frame
        assert result.accepted is True

    def test_rx2_uses_radio_rx2_freq_and_dr(self) -> None:
        radio = _make_radio(rx1_delay=0.0)
        radio._rx2_frequency_hz = 869_525_000
        radio._rx2_data_rate_idx = 0  # SF12BW125
        gw = _make_gateway(rx1_frame=None, rx2_frame=b"\x01")
        clock = FakeClock(start_mono=0.0)
        receiver = ClassAReceiver(radio, gw, clock=clock, rx_window_sec=0.0)

        result = receiver.await_downlink(
            uplink_freq_hz=868_100_000,
            uplink_dr_str="SF7BW125",
            tx_monotonic=0.0,
        )
        assert result.rx2_freq_hz == 869_525_000
        assert result.rx2_data_rate == "SF12BW125"


class TestClassAReceiverTimeout:
    def test_returns_timeout_when_no_frame_anywhere(self) -> None:
        radio = _make_radio(rx1_delay=0.0)
        gw = _make_gateway(rx1_frame=None, rx2_frame=None)
        clock = FakeClock(start_mono=0.0)
        receiver = ClassAReceiver(radio, gw, clock=clock, rx_window_sec=0.0)

        result = receiver.await_downlink(
            uplink_freq_hz=868_100_000,
            uplink_dr_str="SF7BW125",
            tx_monotonic=0.0,
        )

        assert result.window == RxWindow.TIMEOUT
        assert result.downlink_frame is None
        assert result.accepted is False


class TestClassAReceiverCancellation:
    def test_cancelled_during_rx1_wait(self) -> None:
        radio = _make_radio(rx1_delay=100.0)  # very long delay
        gw = MagicMock()
        clock = FakeClock(start_mono=0.0)
        receiver = ClassAReceiver(radio, gw, clock=clock, rx_window_sec=0.1)
        cancel = threading.Event()

        def cancel_soon() -> None:
            import time

            time.sleep(0.02)
            cancel.set()

        import threading as _t

        _t.Thread(target=cancel_soon, daemon=True).start()

        result = receiver.await_downlink(
            uplink_freq_hz=868_100_000,
            uplink_dr_str="SF7BW125",
            tx_monotonic=0.0,
            cancel_event=cancel,
        )
        assert result.window == RxWindow.CANCELLED
        assert result.accepted is False
