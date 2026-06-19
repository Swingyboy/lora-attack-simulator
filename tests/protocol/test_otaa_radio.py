"""Tests for OTAA join channel hopping via Radio."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from lora_attack_toolkit.lorawan.radio import EU868RegionProfile, Radio
from lora_attack_toolkit.lorawan.join import perform_otaa_join_via_radio
from lora_attack_toolkit.config import RadioMetadata


_BASE_CHANNELS = EU868RegionProfile.BASE_UPLINK_CHANNELS_HZ


def _mock_device() -> MagicMock:
    dev = MagicMock()
    dev.new_dev_nonce.return_value = b"\x01\x02"
    dev.build_join_request.return_value = b"\x00" * 23
    dev.runtime.dev_addr_hex = "01020304"
    dev.runtime.cflist = None
    dev.runtime.radio = None
    return dev


def _mock_gateway(response: bytes | None = b"\x20" + b"\x00" * 12) -> MagicMock:
    gw = MagicMock()
    gw.await_downlink.return_value = response
    return gw


def _base_radio() -> RadioMetadata:
    return RadioMetadata(frequency=868_100_000, data_rate="SF7BW125", rssi=-80, snr=7.0)


class TestPerformOtaaJoinViaRadio:
    def test_returns_true_on_success(self) -> None:
        radio = Radio(EU868RegionProfile(), duty_cycle_enforcement=False)
        device = _mock_device()
        gw = _mock_gateway()
        device.apply_join_accept.return_value = None

        result = perform_otaa_join_via_radio(
            device, gw, radio, _base_radio(), seed=0
        )
        assert result is True

    def test_returns_false_on_timeout(self) -> None:
        radio = Radio(EU868RegionProfile(), duty_cycle_enforcement=False)
        device = _mock_device()
        gw = _mock_gateway(response=None)

        result = perform_otaa_join_via_radio(
            device, gw, radio, _base_radio(), seed=0
        )
        assert result is False

    def test_returns_false_on_invalid_join_accept(self) -> None:
        radio = Radio(EU868RegionProfile(), duty_cycle_enforcement=False)
        device = _mock_device()
        gw = _mock_gateway()
        device.apply_join_accept.side_effect = ValueError("bad MIC")

        result = perform_otaa_join_via_radio(
            device, gw, radio, _base_radio(), seed=0
        )
        assert result is False

    def test_deterministic_with_seed(self) -> None:
        """Same seed must produce same channel selection."""
        radio_a = Radio(EU868RegionProfile(), duty_cycle_enforcement=False)
        radio_b = Radio(EU868RegionProfile(), duty_cycle_enforcement=False)

        frequencies: list[int] = []
        for radio in (radio_a, radio_b):
            dev = _mock_device()
            dev.apply_join_accept.return_value = None
            gw = _mock_gateway()
            captured_freq: list[int] = []

            original_forward = gw.forward_uplink.side_effect

            def capture(frame: bytes, meta: RadioMetadata, _f=captured_freq) -> None:
                _f.append(meta.frequency)

            gw.forward_uplink.side_effect = capture
            perform_otaa_join_via_radio(dev, gw, radio, _base_radio(), seed=7)
            frequencies.append(captured_freq[0] if captured_freq else 0)

        assert frequencies[0] == frequencies[1]

    def test_different_seeds_may_select_different_channels(self) -> None:
        """Rotating seeds should cycle through base channels."""
        seen_freqs: set[int] = set()
        for seed in range(len(_BASE_CHANNELS) * 2):
            radio = Radio(EU868RegionProfile(), duty_cycle_enforcement=False)
            dev = _mock_device()
            dev.apply_join_accept.return_value = None
            gw = _mock_gateway()
            captured: list[int] = []

            def capture(frame: bytes, meta: RadioMetadata, _c=captured) -> None:
                _c.append(meta.frequency)

            gw.forward_uplink.side_effect = capture
            perform_otaa_join_via_radio(dev, gw, radio, _base_radio(), seed=seed)
            if captured:
                seen_freqs.add(captured[0])

        # All three base channels should be used across enough seeds
        assert len(seen_freqs) == len(_BASE_CHANNELS)

    def test_records_transmission_on_radio(self) -> None:
        radio = Radio(EU868RegionProfile(), duty_cycle_enforcement=True)
        device = _mock_device()
        gw = _mock_gateway()
        device.apply_join_accept.return_value = None

        perform_otaa_join_via_radio(device, gw, radio, _base_radio(), seed=0)

        # Sub-band should now show a cooldown
        g1_key = radio._get_subband_key(_BASE_CHANNELS[0])
        assert radio._subband_available_after.get(g1_key, 0.0) > 0.0

    def test_cflist_applied_when_present(self) -> None:
        radio = Radio(EU868RegionProfile(), duty_cycle_enforcement=False)
        device = _mock_device()
        # Simulate device that provides a CFList after join
        cflist = bytes([0x78, 0x76, 0x0D, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        device.runtime.cflist = cflist
        gw = _mock_gateway()
        device.apply_join_accept.return_value = None

        with patch.object(radio, "apply_cflist") as mock_cflist:
            perform_otaa_join_via_radio(device, gw, radio, _base_radio(), seed=0)
            mock_cflist.assert_called_once_with(cflist)
