"""Tests for sub-band duty-cycle enforcement in Radio."""

from __future__ import annotations

import pytest

from lora_attack_toolkit.lorawan.radio import EU868RegionProfile, Radio


def _make_radio(enforcement: bool = True) -> Radio:
    return Radio(EU868RegionProfile(), duty_cycle_enforcement=enforcement)


# EU868 g1 sub-band: 868.0–868.6 MHz (1% DC) — contains base channels
_CH_G1_A = 868_100_000  # base channel 0
_CH_G1_B = 868_300_000  # base channel 1
_CH_G1_C = 868_500_000  # base channel 2
# EU868 g3 sub-band: 869.4–869.65 MHz (10% DC) — contains RX2 default
_CH_G3 = 869_525_000
# Channel not in any defined sub-band (out-of-range but freq is valid for testing)
_CH_NONE = 869_000_000  # falls in g2 (0.1 %), not g3


class TestSubbandKey:
    def test_g1_channel_returns_g1_key(self) -> None:
        radio = _make_radio()
        assert radio._get_subband_key(_CH_G1_A) == 868_000_000
        assert radio._get_subband_key(_CH_G1_B) == 868_000_000
        assert radio._get_subband_key(_CH_G1_C) == 868_000_000

    def test_g3_channel_returns_g3_key(self) -> None:
        radio = _make_radio()
        assert radio._get_subband_key(_CH_G3) == 869_400_000

    def test_channel_outside_band_returns_minus_one(self) -> None:
        radio = _make_radio()
        # 867 MHz is below all defined sub-bands in our DUTY_CYCLES list
        assert radio._get_subband_key(867_000_000) == -1


class TestCanTransmit:
    def test_fresh_radio_can_always_transmit(self) -> None:
        radio = _make_radio()
        assert radio.can_transmit(_CH_G1_A, now=0.0)
        assert radio.can_transmit(_CH_G1_B, now=0.0)

    def test_after_record_subband_blocked(self) -> None:
        radio = _make_radio()
        # Record a 1 s transmission at DC=1% → next_tx = now + 1/0.01 = now + 100 s
        radio.record_transmission(_CH_G1_A, airtime_sec=1.0, now=0.0)
        # Same sub-band channel must be blocked
        assert not radio.can_transmit(_CH_G1_A, now=1.0)
        assert not radio.can_transmit(_CH_G1_B, now=1.0)

    def test_different_subband_remains_available(self) -> None:
        radio = _make_radio()
        radio.record_transmission(_CH_G1_A, airtime_sec=1.0, now=0.0)
        # g3 is a different sub-band → must be unaffected
        assert radio.can_transmit(_CH_G3, now=1.0)

    def test_enforcement_disabled_always_true(self) -> None:
        radio = _make_radio(enforcement=False)
        radio.record_transmission(_CH_G1_A, airtime_sec=1.0, now=0.0)
        assert radio.can_transmit(_CH_G1_A, now=0.0)
        assert radio.can_transmit(_CH_G1_B, now=0.0)


class TestRecordTransmission:
    def test_subband_available_after_set_correctly(self) -> None:
        radio = _make_radio()
        airtime = 0.5
        dc = 0.01  # g1 duty cycle
        expected_next = 0.0 + airtime / dc  # = 50.0
        radio.record_transmission(_CH_G1_A, airtime_sec=airtime, now=0.0)
        key = radio._get_subband_key(_CH_G1_A)
        assert abs(radio._subband_available_after[key] - expected_next) < 1e-9

    def test_second_tx_extends_subband_cooldown(self) -> None:
        radio = _make_radio()
        radio.record_transmission(_CH_G1_A, airtime_sec=0.1, now=0.0)
        # Now transmit on B at t=5 — should push subband cooldown further
        radio.record_transmission(_CH_G1_B, airtime_sec=0.1, now=5.0)
        key = radio._get_subband_key(_CH_G1_A)
        # second call: 5.0 + 0.1/0.01 = 15.0 > first call: 0.1/0.01 = 10.0
        assert abs(radio._subband_available_after[key] - 15.0) < 1e-9

    def test_aggregate_not_updated_when_fraction_is_one(self) -> None:
        radio = _make_radio()
        radio.record_transmission(_CH_G1_A, airtime_sec=0.5, now=0.0)
        # Default aggregate fraction = 1.0 → no aggregate tracking
        assert radio._aggregate_available_after == 0.0

    def test_no_double_accounting_enforcement_disabled(self) -> None:
        radio = _make_radio(enforcement=False)
        radio.record_transmission(_CH_G1_A, airtime_sec=1.0, now=0.0)
        assert radio._subband_available_after == {}


class TestAggregateLimit:
    def test_duty_cycle_req_sets_fraction(self) -> None:
        radio = _make_radio()
        # MaxDCycle=4 → fraction = 1/(2^4) = 0.0625
        radio.apply_duty_cycle_req(bytes([0x04]))
        assert abs(radio._aggregate_dc_fraction - 1.0 / 16) < 1e-9

    def test_duty_cycle_req_zero_removes_limit(self) -> None:
        radio = _make_radio()
        radio.apply_duty_cycle_req(bytes([0x04]))
        radio.apply_duty_cycle_req(bytes([0x00]))
        assert radio._aggregate_dc_fraction == 1.0

    def test_aggregate_blocks_after_tx(self) -> None:
        radio = _make_radio()
        radio.apply_duty_cycle_req(bytes([0x04]))  # 1/16
        radio.record_transmission(_CH_G1_A, airtime_sec=0.1, now=0.0)
        # Sub-band blocked until 10 s, aggregate until 1.6 s.
        # both must be False
        assert not radio.can_transmit(_CH_G1_A, now=0.5)

    def test_aggregate_released_before_subband(self) -> None:
        radio = _make_radio()
        radio.apply_duty_cycle_req(bytes([0x04]))  # aggregate fraction = 0.0625
        # airtime 0.1 s:
        #   subband (DC=0.01) → next = 0.0 + 0.1/0.01 = 10.0 s
        #   aggregate (fraction=0.0625) → next = 0.0 + 0.1/0.0625 = 1.6 s
        radio.record_transmission(_CH_G1_A, airtime_sec=0.1, now=0.0)
        # At t=2 aggregate is clear but sub-band still busy
        assert not radio.can_transmit(_CH_G1_A, now=2.0)
        # g3 channel (different sub-band): sub-band clear, but aggregate blocked at t=0.5
        # At t=0.5: aggregate next=1.6 → blocked
        assert not radio.can_transmit(_CH_G3, now=0.5)
        # At t=2: aggregate clear (1.6 < 2) → g3 available
        assert radio.can_transmit(_CH_G3, now=2.0)


class TestNextAvailableTime:
    def test_returns_now_when_available(self) -> None:
        radio = _make_radio()
        assert radio.next_available_time(_CH_G1_A, now=5.0) == 5.0

    def test_returns_subband_wait(self) -> None:
        radio = _make_radio()
        radio.record_transmission(_CH_G1_A, airtime_sec=1.0, now=0.0)
        # sub-band wait: 100 s; aggregate: no restriction
        assert radio.next_available_time(_CH_G1_A, now=1.0) == pytest.approx(100.0)

    def test_returns_max_of_subband_and_aggregate(self) -> None:
        radio = _make_radio()
        radio.apply_duty_cycle_req(bytes([0x02]))  # fraction = 0.25
        # airtime=0.1: subband next = 10.0, aggregate next = 0.4
        radio.record_transmission(_CH_G1_A, airtime_sec=0.1, now=0.0)
        # sub-band dominates
        assert radio.next_available_time(_CH_G1_A, now=0.0) == pytest.approx(10.0)

    def test_enforcement_disabled_returns_now(self) -> None:
        radio = _make_radio(enforcement=False)
        radio.record_transmission(_CH_G1_A, airtime_sec=1.0, now=0.0)
        assert radio.next_available_time(_CH_G1_A, now=0.0) == 0.0


class TestHoppingAcrossSubbands:
    def test_g1_busy_g3_still_available(self) -> None:
        radio = _make_radio()
        radio.record_transmission(_CH_G1_A, airtime_sec=1.0, now=0.0)
        radio.record_transmission(_CH_G1_B, airtime_sec=0.5, now=0.0)
        # g1 sub-band cooldown: max(100, 50) = 100 s → blocked at t=1
        assert not radio.can_transmit(_CH_G1_C, now=1.0)
        # g3 untouched → free
        assert radio.can_transmit(_CH_G3, now=1.0)
