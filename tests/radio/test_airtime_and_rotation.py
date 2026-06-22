"""Tests for LoRa airtime calculation and channel-rotation integration.

EU868ChannelPlan and get_channel_plan have been removed; equivalent behaviour
is tested via the Radio abstraction in tests/radio/test_radio.py.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


# ─── AirtimeCalculator ────────────────────────────────────────────────────────


class TestAirtimeCalculator(unittest.TestCase):
    """Tests for the LoRa airtime formula (Semtech AN1200.13)."""

    def test_sf7bw125_typical(self) -> None:
        from lora_attack_toolkit.lorawan.radio import AirtimeCalculator

        airtime = AirtimeCalculator.calculate("SF7BW125", 23)
        self.assertGreater(airtime, 0.04)
        self.assertLess(airtime, 0.08)

    def test_sf12bw125_is_longer_than_sf7(self) -> None:
        from lora_attack_toolkit.lorawan.radio import AirtimeCalculator

        t7 = AirtimeCalculator.calculate("SF7BW125", 20)
        t12 = AirtimeCalculator.calculate("SF12BW125", 20)
        self.assertGreater(t12, t7)

    def test_larger_payload_is_longer(self) -> None:
        from lora_attack_toolkit.lorawan.radio import AirtimeCalculator

        t_small = AirtimeCalculator.calculate("SF7BW125", 12)
        t_large = AirtimeCalculator.calculate("SF7BW125", 50)
        self.assertGreater(t_large, t_small)

    def test_unknown_data_rate_returns_fallback(self) -> None:
        from lora_attack_toolkit.lorawan.radio import AirtimeCalculator

        airtime = AirtimeCalculator.calculate("UNKNOWN", 20)
        self.assertEqual(airtime, 0.1)


# ─── Integration: join_devnonce channel rotation ──────────────────────────────


class TestJoinDevNonceAttackChannelRotation(unittest.TestCase):
    """Integration-style tests for channel selection inside join_devnonce attack."""

    def setUp(self) -> None:
        from logging import getLogger

        from lora_attack_toolkit.attacks.builtin.join_devnonce import JoinDevNonceAttack
        from lora_attack_toolkit.attacks.context import AttackContext, AttackInput, AttackServices
        from lora_attack_toolkit.attacks.packet_capture import PacketCapture
        from lora_attack_toolkit.config import RadioMetadata, parse_join_devnonce_config
        from lora_attack_toolkit.lorawan.radio import EU868RegionProfile, Radio
        from lora_attack_toolkit.lorawan.time_utils import FakeClock
        from lora_attack_toolkit.runtime.device import SimulatedDevice

        self.attack = JoinDevNonceAttack()
        self.config = parse_join_devnonce_config(
            {
                "valid_join_count": 3,
                "valid_devnonce_start": 1,
                "valid_devnonce_step": 1,
                "final_check": "same_as_last",
                "timing": {"join_accept_timeout_sec": 3.0},
            }
        )
        logger = getLogger("test")
        device = MagicMock(spec=SimulatedDevice)
        device.runtime = MagicMock()
        device.runtime.radio = Radio(EU868RegionProfile(), duty_cycle_enforcement=False)
        device._join_eui = b"\x00" * 8
        device._dev_eui = b"\x00" * 8
        device._app_key = b"\x00" * 16
        gateway = MagicMock()
        gateway.await_downlink.return_value = None
        capture = PacketCapture(logger=logger)
        radio = RadioMetadata(frequency=868_100_000, data_rate="SF7BW125", rssi=-60, snr=7.5)
        self.ctx = AttackContext(
            services=AttackServices(
                device=device, gateway=gateway, logger=logger, capture=capture, metrics=None
            ),
            input=AttackInput(
                typed_config=self.config, expected_behavior=None, radio=radio, timeout_sec=30.0
            ),
            clock=FakeClock(),
        )

    def test_join_requests_use_rotated_frequencies(self) -> None:
        """Generation JoinRequests should rotate 868.1 / 868.3 / 868.5 MHz."""
        recorded_freqs = []

        def capture_freq(payload, radio):
            recorded_freqs.append(radio.frequency)

        self.ctx.gateway.forward_uplink = capture_freq

        self.attack._execute_generation_phase(
            self.ctx,
            self.config,
            self.config.timing,
            __import__(
                "lora_attack_toolkit.attacks.builtin.join_devnonce",
                fromlist=["DevNonceResultCache"],
            ).DevNonceResultCache(10),
        )

        self.assertEqual(len(recorded_freqs), 3)
        self.assertEqual(recorded_freqs[0], 868_100_000)
        self.assertEqual(recorded_freqs[1], 868_300_000)
        self.assertEqual(recorded_freqs[2], 868_500_000)

    def test_no_radio_falls_back_to_ctx_radio(self) -> None:
        """When radio is None, ctx.radio frequency is used unchanged."""
        self.ctx.device.runtime.radio = None
        recorded_freqs = []

        def capture_freq(payload, radio):
            recorded_freqs.append(radio.frequency)

        self.ctx.gateway.forward_uplink = capture_freq

        self.attack._execute_generation_phase(
            self.ctx,
            self.config,
            self.config.timing,
            __import__(
                "lora_attack_toolkit.attacks.builtin.join_devnonce",
                fromlist=["DevNonceResultCache"],
            ).DevNonceResultCache(10),
        )

        self.assertTrue(all(f == 868_100_000 for f in recorded_freqs))


# ─── Integration: send_periodic_uplinks channel rotation ─────────────────────


class TestSendPeriodicUplinksChannelRotation(unittest.TestCase):
    """Tests for uplink channel selection in send_periodic_uplinks."""

    def _make_device(self, radio=None):
        from lora_attack_toolkit.runtime.device import DeviceRuntime, SimulatedDevice

        device = MagicMock(spec=SimulatedDevice)
        device.runtime = MagicMock(spec=DeviceRuntime)
        device.runtime.radio = radio
        device.runtime.uplink_index = 0
        device.runtime.fcnt_up = 1
        device.build_data_uplink.return_value = b"\x00" * 12
        return device

    def _base_radio(self):
        from lora_attack_toolkit.config import RadioMetadata

        return RadioMetadata(frequency=868_100_000, data_rate="SF7BW125", rssi=-70, snr=6.0)

    def _eu868_radio(self, **kwargs):
        from lora_attack_toolkit.lorawan.radio import EU868RegionProfile, Radio

        return Radio(EU868RegionProfile(), duty_cycle_enforcement=False, **kwargs)

    def test_uplinks_rotate_through_eu868_channels(self) -> None:
        from lora_attack_toolkit.lorawan.join import send_periodic_uplinks

        device = self._make_device(radio=self._eu868_radio())
        gateway = MagicMock()
        recorded_freqs = []

        def capture_freq(payload, radio):
            recorded_freqs.append(radio.frequency)

        gateway.forward_uplink.side_effect = capture_freq

        with patch("lora_attack_toolkit.lorawan.join.time.sleep"):
            send_periodic_uplinks(device, gateway, self._base_radio(), count=6, interval_sec=0)

        self.assertEqual(len(recorded_freqs), 6)
        expected = [868_100_000, 868_300_000, 868_500_000, 868_100_000, 868_300_000, 868_500_000]
        self.assertEqual(recorded_freqs, expected)

    def test_uplink_index_incremented_per_uplink(self) -> None:
        from lora_attack_toolkit.lorawan.join import send_periodic_uplinks

        device = self._make_device(radio=self._eu868_radio())
        gateway = MagicMock()

        with patch("lora_attack_toolkit.lorawan.join.time.sleep"):
            send_periodic_uplinks(device, gateway, self._base_radio(), count=4, interval_sec=0)

        self.assertEqual(device.runtime.uplink_index, 4)

    def test_no_radio_uses_base_radio_frequency(self) -> None:
        from lora_attack_toolkit.lorawan.join import send_periodic_uplinks

        device = self._make_device(radio=None)
        gateway = MagicMock()
        recorded_freqs = []

        def capture_freq(payload, radio):
            recorded_freqs.append(radio.frequency)

        gateway.forward_uplink.side_effect = capture_freq

        with patch("lora_attack_toolkit.lorawan.join.time.sleep"):
            send_periodic_uplinks(device, gateway, self._base_radio(), count=3, interval_sec=0)

        self.assertTrue(all(f == 868_100_000 for f in recorded_freqs))

    def test_uplink_after_cflist_uses_extended_channels(self) -> None:
        from lora_attack_toolkit.lorawan.join import send_periodic_uplinks

        radio = self._eu868_radio()
        cflist = bytearray(16)
        cflist[0:3] = (867_100_000 // 100).to_bytes(3, "little")
        cflist[15] = 0
        radio.apply_cflist(bytes(cflist))

        device = self._make_device(radio=radio)
        gateway = MagicMock()
        recorded_freqs = []

        def capture_freq(payload, radio_meta):
            recorded_freqs.append(radio_meta.frequency)

        gateway.forward_uplink.side_effect = capture_freq

        with patch("lora_attack_toolkit.lorawan.join.time.sleep"):
            send_periodic_uplinks(device, gateway, self._base_radio(), count=4, interval_sec=0)

        self.assertIn(867_100_000, recorded_freqs)
