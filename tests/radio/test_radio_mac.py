"""Tests for Radio MAC command application (P0 §5).

Verifies:
- LinkADRReq updates data-rate and TX power in Radio._data_rate/_tx_power
- Invalid parameters produce correct negative ACK bits
- Rollback: previous state preserved when command is rejected
- RXParamSetupReq, NewChannelReq, RXTimingSetupReq, DutyCycleReq
"""

from __future__ import annotations

import unittest

from lora_attack_toolkit.lorawan.radio import (

    EU868RegionProfile,
    EU868_DR_TABLE,
    EU868_TX_POWER_TABLE,
    Radio,
)
import pytest

pytestmark = pytest.mark.unit


def _make_radio(duty_cycle: bool = False) -> Radio:
    return Radio(EU868RegionProfile(), duty_cycle_enforcement=duty_cycle)


def _link_adr_payload(dr: int, tp: int, ch_mask: int = 0x00FF, redundancy: int = 0) -> bytes:
    return bytes([(dr << 4) | (tp & 0x0F)]) + ch_mask.to_bytes(2, "little") + bytes([redundancy])


class TestRadioLinkADRReq(unittest.TestCase):
    """LinkADRReq application, validation, and ACK bits."""

    def test_valid_params_accepted_status_0x07(self) -> None:
        radio = _make_radio()
        payload = _link_adr_payload(dr=5, tp=1, ch_mask=0x00FF)
        status = radio.apply_link_adr_req(payload)
        self.assertEqual(status, 0x07)

    def test_dr_applied_after_acceptance(self) -> None:
        radio = _make_radio()
        payload = _link_adr_payload(dr=3, tp=0, ch_mask=0x00FF)
        radio.apply_link_adr_req(payload)
        self.assertEqual(radio.get_current_data_rate(), EU868_DR_TABLE[3])

    def test_tx_power_applied_after_acceptance(self) -> None:
        radio = _make_radio()
        payload = _link_adr_payload(dr=5, tp=2, ch_mask=0x00FF)
        radio.apply_link_adr_req(payload)
        self.assertEqual(radio.get_current_tx_power(), EU868_TX_POWER_TABLE[2])

    def test_channel_mask_applied(self) -> None:
        radio = _make_radio()
        payload = _link_adr_payload(dr=5, tp=0, ch_mask=0x00FF)
        radio.apply_link_adr_req(payload)
        self.assertEqual(radio.ch_mask, 0x00FF)

    def test_keep_current_dr_0x0f(self) -> None:
        """DR=0x0F means 'keep current' — must still succeed (bit 1 ACK set)."""
        radio = _make_radio()
        original_dr = radio.get_current_data_rate()
        payload = _link_adr_payload(dr=0x0F, tp=0, ch_mask=0x00FF)
        status = radio.apply_link_adr_req(payload)
        self.assertEqual(status, 0x07)
        self.assertEqual(radio.get_current_data_rate(), original_dr)

    def test_keep_current_tp_0x0f(self) -> None:
        """TXPower=0x0F means 'keep current'."""
        radio = _make_radio()
        original_tp = radio.get_current_tx_power()
        payload = _link_adr_payload(dr=5, tp=0x0F, ch_mask=0x00FF)
        status = radio.apply_link_adr_req(payload)
        self.assertEqual(status, 0x07)
        self.assertEqual(radio.get_current_tx_power(), original_tp)

    def test_invalid_dr_rejects_command(self) -> None:
        radio = _make_radio()
        original_dr = radio.get_current_data_rate()
        # DR=6 is not valid in EU868 (only 0-5 and 0xF)
        payload = _link_adr_payload(dr=6, tp=0, ch_mask=0x00FF)
        status = radio.apply_link_adr_req(payload)
        # DataRateACK bit (bit 1) must be 0 → status < 0x07
        self.assertNotEqual(status, 0x07)
        # State must be unchanged
        self.assertEqual(radio.get_current_data_rate(), original_dr)

    def test_invalid_tp_rejects_command(self) -> None:
        radio = _make_radio()
        original_tp = radio.get_current_tx_power()
        # TX power index 8 is out of range (0-7 valid)
        payload = _link_adr_payload(dr=5, tp=8, ch_mask=0x00FF)
        status = radio.apply_link_adr_req(payload)
        self.assertNotEqual(status, 0x07)
        self.assertEqual(radio.get_current_tx_power(), original_tp)

    def test_disable_all_base_channels_rejected(self) -> None:
        radio = _make_radio()
        original_mask = radio.ch_mask
        # ch_mask = 0x0000 would disable all base channels → reject
        payload = _link_adr_payload(dr=5, tp=0, ch_mask=0x0000)
        status = radio.apply_link_adr_req(payload)
        self.assertNotEqual(status & 0x04, 0x04)  # ChannelMaskACK bit clear
        self.assertEqual(radio.ch_mask, original_mask)

    def test_short_payload_returns_reject(self) -> None:
        radio = _make_radio()
        status = radio.apply_link_adr_req(b"\x50\xff")
        self.assertEqual(status, 0x00)

    def test_subsequent_uplinks_use_updated_data_rate(self) -> None:
        """After acceptance, select_uplink_channel uses the new DR."""
        radio = _make_radio()
        payload = _link_adr_payload(dr=0, tp=0, ch_mask=0x00FF)  # DR0 = SF12
        radio.apply_link_adr_req(payload)
        tx = radio.select_uplink_channel(0)
        self.assertEqual(tx.data_rate, EU868_DR_TABLE[0])

    def test_ch_mask_cntl_6_enables_all(self) -> None:
        """ChMaskCntl=6 means 'all channels on'."""
        radio = _make_radio()
        redundancy = (6 << 4) | 0x01  # ChMaskCntl=6
        payload = _link_adr_payload(dr=5, tp=0, ch_mask=0x0000, redundancy=redundancy)
        status = radio.apply_link_adr_req(payload)
        self.assertEqual(status, 0x07)
        self.assertEqual(radio.ch_mask, 0xFFFF)


class TestRadioRxParamSetupReq(unittest.TestCase):
    """RXParamSetupReq sets RX1 offset, RX2 DR, and RX2 frequency."""

    def _rx_param_payload(self, rx1_offset: int, rx2_dr: int, freq_hz: int) -> bytes:
        dl_settings = ((rx1_offset & 0x07) << 4) | (rx2_dr & 0x0F)
        freq_bytes = (freq_hz // 100).to_bytes(3, "little")
        return bytes([dl_settings]) + freq_bytes

    def test_valid_params_accepted(self) -> None:
        radio = _make_radio()
        payload = self._rx_param_payload(rx1_offset=1, rx2_dr=0, freq_hz=869_525_000)
        status = radio.apply_rx_param_setup_req(payload)
        self.assertEqual(status, 0x07)

    def test_rx1_offset_applied(self) -> None:
        radio = _make_radio()
        payload = self._rx_param_payload(rx1_offset=3, rx2_dr=0, freq_hz=869_525_000)
        radio.apply_rx_param_setup_req(payload)
        self.assertEqual(radio.rx1_dr_offset, 3)

    def test_rx2_dr_applied(self) -> None:
        radio = _make_radio()
        payload = self._rx_param_payload(rx1_offset=0, rx2_dr=2, freq_hz=869_525_000)
        radio.apply_rx_param_setup_req(payload)
        self.assertEqual(radio.rx2_data_rate_idx, 2)

    def test_rx2_frequency_applied(self) -> None:
        radio = _make_radio()
        payload = self._rx_param_payload(rx1_offset=0, rx2_dr=0, freq_hz=868_100_000)
        radio.apply_rx_param_setup_req(payload)
        self.assertEqual(radio.rx2_frequency_hz, 868_100_000)

    def test_invalid_rx1_offset_rejected(self) -> None:
        radio = _make_radio()
        original_offset = radio.rx1_dr_offset
        # RX1 DR offset > 5 is invalid for EU868
        payload = self._rx_param_payload(rx1_offset=7, rx2_dr=0, freq_hz=869_525_000)
        status = radio.apply_rx_param_setup_req(payload)
        self.assertNotEqual(status, 0x07)
        self.assertEqual(radio.rx1_dr_offset, original_offset)

    def test_out_of_range_frequency_rejected(self) -> None:
        radio = _make_radio()
        original_freq = radio.rx2_frequency_hz
        # 900 MHz is outside EU868 range (863-870 MHz)
        payload = self._rx_param_payload(rx1_offset=0, rx2_dr=0, freq_hz=900_000_000)
        status = radio.apply_rx_param_setup_req(payload)
        self.assertNotEqual(status & 0x01, 0x01)  # ChannelACK clear
        self.assertEqual(radio.rx2_frequency_hz, original_freq)


class TestRadioRxTimingSetupReq(unittest.TestCase):
    """RXTimingSetupReq updates RX1 delay."""

    def test_delay_1_second_applied(self) -> None:
        radio = _make_radio()
        radio.apply_rx_timing_setup_req(bytes([0x01]))
        self.assertAlmostEqual(radio.rx1_delay_sec, 1.0)

    def test_delay_5_seconds_applied(self) -> None:
        radio = _make_radio()
        radio.apply_rx_timing_setup_req(bytes([0x05]))
        self.assertAlmostEqual(radio.rx1_delay_sec, 5.0)

    def test_delay_0_treated_as_1(self) -> None:
        """Per LoRaWAN spec §5.7: Del=0 means 1 second."""
        radio = _make_radio()
        radio.apply_rx_timing_setup_req(bytes([0x00]))
        self.assertAlmostEqual(radio.rx1_delay_sec, 1.0)

    def test_empty_payload_no_change(self) -> None:
        radio = _make_radio()
        original_delay = radio.rx1_delay_sec
        radio.apply_rx_timing_setup_req(b"")
        self.assertAlmostEqual(radio.rx1_delay_sec, original_delay)


class TestRadioNewChannelReq(unittest.TestCase):
    """NewChannelReq adds channels to the active set."""

    def test_valid_channel_accepted(self) -> None:
        radio = _make_radio()
        # ch_index=3, freq=867.1 MHz, DR range 0-5
        freq = 867_100_000
        payload = bytes([3]) + (freq // 100).to_bytes(3, "little") + bytes([(5 << 4) | 0])
        status = radio.apply_new_channel_req(payload)
        self.assertEqual(status, 0x03)

    def test_out_of_range_frequency_rejected(self) -> None:
        radio = _make_radio()
        freq = 900_000_000  # outside EU868
        payload = bytes([3]) + (freq // 100).to_bytes(3, "little") + bytes([(5 << 4) | 0])
        status = radio.apply_new_channel_req(payload)
        self.assertEqual(status & 0x01, 0)  # ChannelFreqOK bit clear

    def test_short_payload_rejected(self) -> None:
        radio = _make_radio()
        status = radio.apply_new_channel_req(b"\x03\xff\xff")
        self.assertEqual(status, 0x00)


class TestRadioDutyCycleReq(unittest.TestCase):
    """DutyCycleReq is logged/stored without crashing."""

    def test_does_not_raise(self) -> None:
        radio = _make_radio()
        # Should not raise any exception
        radio.apply_duty_cycle_req(bytes([0x05]))

    def test_empty_payload_no_crash(self) -> None:
        radio = _make_radio()
        radio.apply_duty_cycle_req(b"")  # must not raise


if __name__ == "__main__":
    unittest.main()


class TestChannelMaskFiltering(unittest.TestCase):
    """get_active_uplink_channels() respects the channel mask."""

    def test_all_channels_enabled_by_default(self) -> None:
        radio = _make_radio()
        # Default mask 0x00FF enables all 8 channels (3 base + up to 5 CFList).
        # With no CFList, only the 3 base channels exist, all enabled.
        channels = radio.get_active_uplink_channels()
        self.assertEqual(len(channels), 3)

    def test_disabled_cflist_channels_excluded(self) -> None:
        """After LinkADRReq disables channels 3–7, CFList channels are dropped."""
        radio = _make_radio()
        # Add 2 CFList channels (indices 3 and 4)
        cflist = bytes.fromhex("184f84e8568400000000000000000000")
        radio.apply_cflist(cflist)
        self.assertEqual(len(radio.get_active_uplink_channels()), 5)  # 3 base + 2 cflist

        # Disable channels 3 and 4 (keep bits 0-2 only)
        payload = _link_adr_payload(dr=5, tp=1, ch_mask=0x0007)
        status = radio.apply_link_adr_req(payload)
        self.assertEqual(status & 0x01, 1, "channel_mask_ack must be set")

        channels = radio.get_active_uplink_channels()
        self.assertEqual(len(channels), 3, "only 3 mandatory base channels should remain")

    def test_re_enabling_channel_restores_it(self) -> None:
        """Re-enabling a previously disabled CFList channel adds it back."""
        radio = _make_radio()
        cflist = bytes.fromhex("184f84e8568400000000000000000000")
        radio.apply_cflist(cflist)

        # Disable channels 3-4
        radio.apply_link_adr_req(_link_adr_payload(dr=5, tp=1, ch_mask=0x0007))
        self.assertEqual(len(radio.get_active_uplink_channels()), 3)

        # Re-enable all
        radio.apply_link_adr_req(_link_adr_payload(dr=5, tp=1, ch_mask=0x001F))
        self.assertEqual(len(radio.get_active_uplink_channels()), 5)

    def test_selector_never_returns_disabled_freq(self) -> None:
        """select_uplink_channel always picks a frequency that is enabled."""
        radio = _make_radio()
        cflist = bytes.fromhex("184f84e8568400000000000000000000")
        radio.apply_cflist(cflist)

        # Disable the first CFList channel (index 3)
        radio.apply_link_adr_req(_link_adr_payload(dr=5, tp=1, ch_mask=0x0017))

        active_freqs = set(radio.get_active_uplink_channels())
        for i in range(20):
            params = radio.select_uplink_channel(i)
            self.assertIn(params.frequency_hz, active_freqs, f"attempt {i}: disabled freq selected")

    def test_mandatory_base_channels_always_included(self) -> None:
        """Base channels 0-2 are always included, even if mask bits say otherwise."""
        radio = _make_radio()
        # Set mask to 0x0000 — no channel explicitly enabled.
        # Mandatory base channels must still appear.
        payload = _link_adr_payload(dr=5, tp=1, ch_mask=0x0000)
        # apply_link_adr_req should reject a mask that disables all base channels
        status = radio.apply_link_adr_req(payload)
        # Channel mask ACK bit should be 0 (rejected), OR channels remain
        if status & 0x01:
            # If for some reason accepted, base channels must still be present
            channels = radio.get_active_uplink_channels()
            base = EU868RegionProfile().BASE_UPLINK_CHANNELS_HZ
            for freq in base:
                self.assertIn(freq, channels)
        # else rejection is also correct behavior (existing test covers this)
