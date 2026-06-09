"""Tests for the region channel plan abstraction."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, Mock, patch
from dataclasses import replace

from lora_attack_toolkit.lorawan.channel_plan import (
    EU868ChannelPlan,
    PassthroughChannelPlan,
    get_channel_plan,
    Channel,
    _EU868_JOIN_FREQUENCIES_HZ,
    _EU868_DEFAULT_UPLINK_FREQUENCIES_HZ,
)


class TestEU868JoinChannels(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = EU868ChannelPlan()

    def test_join_channels_are_three_default_eu868(self) -> None:
        channels = self.plan.get_join_channels()
        self.assertEqual(len(channels), 3)
        freqs = [c.frequency_hz for c in channels]
        self.assertEqual(freqs, [868_100_000, 868_300_000, 868_500_000])

    def test_join_channel_rotation_attempt_0(self) -> None:
        self.assertEqual(self.plan.select_join_channel(0).frequency_hz, 868_100_000)

    def test_join_channel_rotation_attempt_1(self) -> None:
        self.assertEqual(self.plan.select_join_channel(1).frequency_hz, 868_300_000)

    def test_join_channel_rotation_attempt_2(self) -> None:
        self.assertEqual(self.plan.select_join_channel(2).frequency_hz, 868_500_000)

    def test_join_channel_wraps_at_3(self) -> None:
        self.assertEqual(self.plan.select_join_channel(3).frequency_hz, 868_100_000)

    def test_join_channel_wraps_at_4(self) -> None:
        self.assertEqual(self.plan.select_join_channel(4).frequency_hz, 868_300_000)

    def test_join_channel_large_index(self) -> None:
        # 9 = 3*3 → index 0 → 868.1
        self.assertEqual(self.plan.select_join_channel(9).frequency_hz, 868_100_000)


class TestEU868DefaultUplinkChannels(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = EU868ChannelPlan()

    def test_default_uplink_channels(self) -> None:
        channels = self.plan.get_uplink_channels()
        freqs = [c.frequency_hz for c in channels]
        self.assertEqual(freqs, [868_100_000, 868_300_000, 868_500_000])

    def test_uplink_channel_rotation(self) -> None:
        self.assertEqual(self.plan.select_uplink_channel(0).frequency_hz, 868_100_000)
        self.assertEqual(self.plan.select_uplink_channel(1).frequency_hz, 868_300_000)
        self.assertEqual(self.plan.select_uplink_channel(2).frequency_hz, 868_500_000)
        self.assertEqual(self.plan.select_uplink_channel(3).frequency_hz, 868_100_000)


class TestEU868CFList(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = EU868ChannelPlan()

    def _make_cflist(self, freqs_hz: list[int], cflist_type: int = 0) -> bytes:
        """Build a 16-byte CFList from frequency values (in Hz)."""
        data = bytearray(16)
        for i, f in enumerate(freqs_hz[:5]):
            raw = (f // 100).to_bytes(3, "little")
            data[i * 3: i * 3 + 3] = raw
        data[15] = cflist_type
        return bytes(data)

    def test_cflist_adds_new_channels(self) -> None:
        cflist = self._make_cflist([867_100_000, 867_300_000, 867_500_000])
        self.plan.apply_cflist(cflist)
        freqs = [c.frequency_hz for c in self.plan.get_uplink_channels()]
        self.assertIn(867_100_000, freqs)
        self.assertIn(867_300_000, freqs)
        self.assertIn(867_500_000, freqs)

    def test_cflist_does_not_duplicate_existing_channels(self) -> None:
        cflist = self._make_cflist([868_100_000, 867_100_000])
        self.plan.apply_cflist(cflist)
        freqs = [c.frequency_hz for c in self.plan.get_uplink_channels()]
        self.assertEqual(freqs.count(868_100_000), 1)

    def test_cflist_zero_slots_ignored(self) -> None:
        cflist = self._make_cflist([867_100_000, 0, 0])
        self.plan.apply_cflist(cflist)
        freqs = [c.frequency_hz for c in self.plan.get_uplink_channels()]
        self.assertIn(867_100_000, freqs)
        self.assertNotIn(0, freqs)

    def test_cflist_type_1_ignored(self) -> None:
        cflist = self._make_cflist([867_100_000], cflist_type=1)
        before = list(self.plan.get_uplink_channels())
        self.plan.apply_cflist(cflist)
        after = list(self.plan.get_uplink_channels())
        self.assertEqual(
            [c.frequency_hz for c in before],
            [c.frequency_hz for c in after],
        )

    def test_cflist_none_is_noop(self) -> None:
        before = [c.frequency_hz for c in self.plan.get_uplink_channels()]
        self.plan.apply_cflist(None)
        after = [c.frequency_hz for c in self.plan.get_uplink_channels()]
        self.assertEqual(before, after)

    def test_cflist_wrong_length_is_noop(self) -> None:
        before = [c.frequency_hz for c in self.plan.get_uplink_channels()]
        self.plan.apply_cflist(b"\x00" * 10)
        after = [c.frequency_hz for c in self.plan.get_uplink_channels()]
        self.assertEqual(before, after)

    def test_cflist_full_5_channels(self) -> None:
        new_freqs = [867_100_000, 867_300_000, 867_500_000, 867_700_000, 867_900_000]
        cflist = self._make_cflist(new_freqs)
        self.plan.apply_cflist(cflist)
        freqs = set(c.frequency_hz for c in self.plan.get_uplink_channels())
        for f in new_freqs:
            self.assertIn(f, freqs)


class TestPassthroughChannelPlan(unittest.TestCase):
    def test_returns_single_fixed_channel(self) -> None:
        plan = PassthroughChannelPlan("US915", 902_300_000)
        self.assertEqual(len(plan.get_join_channels()), 1)
        self.assertEqual(plan.get_join_channels()[0].frequency_hz, 902_300_000)

    def test_join_channel_always_same(self) -> None:
        plan = PassthroughChannelPlan("US915", 902_300_000)
        for i in range(5):
            self.assertEqual(plan.select_join_channel(i).frequency_hz, 902_300_000)

    def test_cflist_is_noop(self) -> None:
        plan = PassthroughChannelPlan("US915", 902_300_000)
        plan.apply_cflist(b"\x00" * 16)  # must not raise
        self.assertEqual(plan.get_uplink_channels()[0].frequency_hz, 902_300_000)


class TestGetChannelPlan(unittest.TestCase):
    def test_eu868_returns_eu868_plan(self) -> None:
        plan = get_channel_plan("EU868")
        self.assertIsInstance(plan, EU868ChannelPlan)
        self.assertEqual(plan.region, "EU868")

    def test_eu868_case_insensitive(self) -> None:
        plan = get_channel_plan("eu868")
        self.assertIsInstance(plan, EU868ChannelPlan)

    def test_unknown_region_returns_passthrough(self) -> None:
        plan = get_channel_plan("US915", default_frequency_hz=902_300_000)
        self.assertIsInstance(plan, PassthroughChannelPlan)
        self.assertEqual(plan.get_join_channels()[0].frequency_hz, 902_300_000)

    def test_default_frequency_used_for_passthrough(self) -> None:
        plan = get_channel_plan("AS923", default_frequency_hz=923_200_000)
        self.assertEqual(plan.get_uplink_channels()[0].frequency_hz, 923_200_000)


class TestJoinDevNonceAttackChannelRotation(unittest.TestCase):
    """Integration-style tests for channel selection inside join_devnonce attack."""

    def setUp(self) -> None:
        from logging import getLogger
        from unittest.mock import MagicMock
        from lora_attack_toolkit.attacks.builtin.join_devnonce import JoinDevNonceAttack
        from lora_attack_toolkit.attacks.context import AttackContext, AttackInput, AttackServices
        from lora_attack_toolkit.attacks.packet_capture import PacketCapture
        from lora_attack_toolkit.config import RadioMetadata
        from lora_attack_toolkit.config import parse_join_devnonce_config
        from lora_attack_toolkit.runtime.device import SimulatedDevice
        from lora_attack_toolkit.lorawan.radio import EU868RegionProfile, Radio

        self.attack = JoinDevNonceAttack()
        self.config = parse_join_devnonce_config({
            "valid_join_count": 3,
            "valid_devnonce_start": 1,
            "valid_devnonce_step": 1,
            "final_check": "same_as_last",
            "timing": {
                "join_accept_timeout_sec": 3.0,
                "rx1_delay_sec": 1.0,
                "rx1_window_sec": 1.0,
                "rx2_delay_sec": 2.0,
                "rx2_window_sec": 1.0,
            },
        })
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
            services=AttackServices(device=device, gateway=gateway, logger=logger, capture=capture, metrics=None),
            input=AttackInput(typed_config=self.config, expected_behavior=None, radio=radio, timeout_sec=30.0),
        )

    def test_join_requests_use_rotated_frequencies(self) -> None:
        """The three generation JoinRequests should use 868.1, 868.3, 868.5 MHz."""
        recorded_freqs = []

        original_forward = self.ctx.gateway.forward_uplink

        def capture_freq(payload, radio):
            recorded_freqs.append(radio.frequency)

        self.ctx.gateway.forward_uplink = capture_freq

        # float("inf") makes _sleep_until and the RX-window while-loops exit immediately:
        # deadline = inf + offset = inf; while inf < inf → False.
        with patch("lora_attack_toolkit.attacks.builtin.join_devnonce.time.monotonic", return_value=float("inf")), \
             patch("lora_attack_toolkit.attacks.builtin.join_devnonce.time.sleep"):
            self.attack._execute_generation_phase(
                self.ctx, self.config,
                self.config.timing,
                __import__("lora_attack_toolkit.attacks.builtin.join_devnonce",
                            fromlist=["DevNonceResultCache"]).DevNonceResultCache(10),
            )

        # 3 generation JoinRequests
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

        with patch("lora_attack_toolkit.attacks.builtin.join_devnonce.time.monotonic", return_value=float("inf")), \
             patch("lora_attack_toolkit.attacks.builtin.join_devnonce.time.sleep"):
            self.attack._execute_generation_phase(
                self.ctx, self.config,
                self.config.timing,
                __import__("lora_attack_toolkit.attacks.builtin.join_devnonce",
                            fromlist=["DevNonceResultCache"]).DevNonceResultCache(10),
            )

        self.assertTrue(all(f == 868_100_000 for f in recorded_freqs))


class TestSendPeriodicUplinksChannelRotation(unittest.TestCase):
    """Tests for uplink channel selection in send_periodic_uplinks."""

    def _make_device(self, radio=None):
        from unittest.mock import MagicMock
        from lora_attack_toolkit.runtime.device import SimulatedDevice, DeviceRuntime

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

    def _eu868_radio(self, **kwargs) -> "Radio":
        from lora_attack_toolkit.lorawan.radio import EU868RegionProfile, Radio
        return Radio(EU868RegionProfile(), duty_cycle_enforcement=False, **kwargs)

    def test_uplinks_rotate_through_eu868_channels(self) -> None:
        """send_periodic_uplinks should rotate 868.1 / 868.3 / 868.5 for EU868."""
        from unittest.mock import patch, MagicMock
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
        """runtime.uplink_index should advance by 1 for each uplink sent."""
        from unittest.mock import patch, MagicMock
        from lora_attack_toolkit.lorawan.join import send_periodic_uplinks

        device = self._make_device(radio=self._eu868_radio())
        gateway = MagicMock()

        with patch("lora_attack_toolkit.lorawan.join.time.sleep"):
            send_periodic_uplinks(device, gateway, self._base_radio(), count=4, interval_sec=0)

        self.assertEqual(device.runtime.uplink_index, 4)

    def test_no_radio_uses_base_radio_frequency(self) -> None:
        """When radio is None, base radio frequency is used unchanged."""
        from unittest.mock import patch, MagicMock
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
        """After apply_cflist, uplinks should rotate over the extended channel list."""
        from unittest.mock import patch, MagicMock
        from lora_attack_toolkit.lorawan.join import send_periodic_uplinks

        radio = self._eu868_radio()
        cflist = bytearray(16)
        freq_raw = (867_100_000 // 100).to_bytes(3, "little")
        cflist[0:3] = freq_raw
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

        # After CFList: [868.1, 868.3, 868.5, 867.1] → 4 uplinks cover all
        self.assertIn(867_100_000, recorded_freqs)


# ─── Duty Cycle tests ─────────────────────────────────────────────────────────


class TestAirtimeCalculator(unittest.TestCase):
    """Tests for the LoRa airtime formula."""

    def test_sf7bw125_typical(self) -> None:
        from lora_attack_toolkit.lorawan.channel_plan import AirtimeCalculator

        airtime = AirtimeCalculator.calculate("SF7BW125", 23)
        # Known-good range: ~46–56 ms for SF7BW125 with 23-byte payload
        self.assertGreater(airtime, 0.04)
        self.assertLess(airtime, 0.08)

    def test_sf12bw125_is_longer_than_sf7(self) -> None:
        from lora_attack_toolkit.lorawan.channel_plan import AirtimeCalculator

        t7 = AirtimeCalculator.calculate("SF7BW125", 20)
        t12 = AirtimeCalculator.calculate("SF12BW125", 20)
        self.assertGreater(t12, t7)

    def test_larger_payload_is_longer(self) -> None:
        from lora_attack_toolkit.lorawan.channel_plan import AirtimeCalculator

        t_small = AirtimeCalculator.calculate("SF7BW125", 12)
        t_large = AirtimeCalculator.calculate("SF7BW125", 50)
        self.assertGreater(t_large, t_small)

    def test_unknown_data_rate_returns_fallback(self) -> None:
        from lora_attack_toolkit.lorawan.channel_plan import AirtimeCalculator

        airtime = AirtimeCalculator.calculate("UNKNOWN", 20)
        self.assertEqual(airtime, 0.1)


class TestEU868DutyCycleEnforcement(unittest.TestCase):
    """Tests for EU868 Duty Cycle enforcement logic."""

    def _plan(self, enforcement: bool = True) -> EU868ChannelPlan:
        return EU868ChannelPlan(duty_cycle_enforcement=enforcement)

    def test_supports_duty_cycle_true(self) -> None:
        self.assertTrue(self._plan().supports_duty_cycle())

    def test_passthrough_does_not_support_duty_cycle(self) -> None:
        plan = PassthroughChannelPlan("US915", 902_300_000)
        self.assertFalse(plan.supports_duty_cycle())

    def test_can_transmit_fresh_plan(self) -> None:
        plan = self._plan()
        ch = plan.get_join_channels()[0]
        self.assertTrue(plan.can_transmit(ch, 1_000.0))

    def test_can_transmit_false_after_record(self) -> None:
        plan = self._plan()
        ch = plan.get_join_channels()[0]
        plan.record_transmission(ch, airtime_sec=0.05, now=1_000.0)
        # 1 % duty cycle → next available ≈ now + 0.05/0.01 = 5 s later
        self.assertFalse(plan.can_transmit(ch, 1_000.1))

    def test_can_transmit_true_after_time_off(self) -> None:
        plan = self._plan()
        ch = plan.get_join_channels()[0]
        plan.record_transmission(ch, airtime_sec=0.05, now=1_000.0)
        next_avail = plan.next_available_time(ch, 1_000.0)
        self.assertTrue(plan.can_transmit(ch, next_avail + 0.001))

    def test_next_available_time_formula(self) -> None:
        plan = self._plan()
        ch = plan.get_join_channels()[0]
        plan.record_transmission(ch, airtime_sec=0.05, now=1_000.0)
        # 1 %: 0.05 / 0.01 = 5 s → available at 1005
        expected = 1_005.0
        self.assertAlmostEqual(plan.next_available_time(ch, 1_000.0), expected, places=3)

    def test_next_available_time_g2_sub_band(self) -> None:
        plan = self._plan()
        ch = Channel(869_100_000, "SF7BW125")  # g2: 0.1 %
        plan.record_transmission(ch, airtime_sec=0.05, now=1_000.0)
        # 0.1 %: 0.05 / 0.001 = 50 s
        self.assertAlmostEqual(plan.next_available_time(ch, 1_000.0), 1_050.0, places=3)

    def test_next_available_time_g3_sub_band(self) -> None:
        plan = self._plan()
        ch = Channel(869_500_000, "SF7BW125")  # g3: 10 %
        plan.record_transmission(ch, airtime_sec=0.05, now=1_000.0)
        # 10 %: 0.05 / 0.10 = 0.5 s
        self.assertAlmostEqual(plan.next_available_time(ch, 1_000.0), 1_000.5, places=3)

    def test_duty_cycle_disabled_can_always_transmit(self) -> None:
        plan = self._plan(enforcement=False)
        ch = plan.get_join_channels()[0]
        plan.record_transmission(ch, airtime_sec=10.0, now=1_000.0)
        self.assertTrue(plan.can_transmit(ch, 1_000.0))

    def test_record_transmission_disabled_is_noop(self) -> None:
        plan = self._plan(enforcement=False)
        ch = plan.get_join_channels()[0]
        plan.record_transmission(ch, airtime_sec=10.0, now=1_000.0)
        # Should not have updated anything
        self.assertEqual(plan._channel_available_after, {})


class TestEU868DutyCycleChannelSelection(unittest.TestCase):
    """Tests for channel selection with Duty Cycle enforcement."""

    def setUp(self) -> None:
        self.plan = EU868ChannelPlan(duty_cycle_enforcement=True)
        self.t0 = 1_000.0

    def _record_all(self, airtime: float = 0.05) -> None:
        """Mark all default channels as busy."""
        for ch in self.plan.get_join_channels():
            self.plan.record_transmission(ch, airtime_sec=airtime, now=self.t0)

    def test_preferred_available_channel_returned(self) -> None:
        ch = self.plan.select_join_channel(0, now=self.t0)
        self.assertEqual(ch.frequency_hz, 868_100_000)

    def test_preferred_channel_unavailable_falls_back(self) -> None:
        # Block preferred channel (868.1)
        self.plan.record_transmission(
            Channel(868_100_000, "SF7BW125"), airtime_sec=0.05, now=self.t0
        )
        ch = self.plan.select_join_channel(0, now=self.t0 + 0.001)
        self.assertNotEqual(ch.frequency_hz, 868_100_000)

    def test_all_unavailable_waits_then_returns(self) -> None:
        self._record_all()
        sleep_calls: list[float] = []

        with patch("lora_attack_toolkit.lorawan.channel_plan._time.sleep", side_effect=sleep_calls.append):
            ch = self.plan.select_join_channel(0, now=self.t0 + 0.001)

        # Must have waited at least once
        self.assertEqual(len(sleep_calls), 1)
        self.assertGreater(sleep_calls[0], 0)

    def test_channel_reserved_after_selection(self) -> None:
        ch = self.plan.select_join_channel(0, now=self.t0)
        # The selected channel should now be unavailable
        self.assertFalse(self.plan.can_transmit(ch, self.t0 + 0.001))

    def test_uplink_channel_selection_with_duty_cycle(self) -> None:
        # Block 868.1 then ask for uplink_index=0 (which maps to 868.1)
        self.plan.record_transmission(
            Channel(868_100_000, "SF7BW125"), airtime_sec=0.05, now=self.t0
        )
        ch = self.plan.select_uplink_channel(0, now=self.t0 + 0.001)
        self.assertNotEqual(ch.frequency_hz, 868_100_000)

    def test_no_now_skips_duty_cycle(self) -> None:
        self._record_all()
        # Without now, selection ignores duty cycle → returns natural rotation
        ch = self.plan.select_join_channel(0)
        self.assertEqual(ch.frequency_hz, 868_100_000)

    def test_enforcement_disabled_ignores_busy_channels(self) -> None:
        plan = EU868ChannelPlan(duty_cycle_enforcement=False)
        ch = plan.get_join_channels()[0]
        plan.record_transmission(ch, airtime_sec=10.0, now=self.t0)
        selected = plan.select_join_channel(0, now=self.t0 + 0.001)
        self.assertEqual(selected.frequency_hz, ch.frequency_hz)


class TestEU868DutyCycleLogging(unittest.TestCase):
    """Tests for Duty Cycle log messages."""

    def test_enabled_logs_on_init(self) -> None:
        import logging
        logger = MagicMock(spec=logging.Logger)
        EU868ChannelPlan(duty_cycle_enforcement=True, logger=logger)
        logger.info.assert_called_once_with("EU868 Duty Cycle enabled")

    def test_disabled_logs_on_init(self) -> None:
        import logging
        logger = MagicMock(spec=logging.Logger)
        EU868ChannelPlan(duty_cycle_enforcement=False, logger=logger)
        logger.info.assert_called_once_with("EU868 Duty Cycle enforcement disabled")

    def test_selected_channel_logged(self) -> None:
        import logging
        logger = MagicMock(spec=logging.Logger)
        plan = EU868ChannelPlan(duty_cycle_enforcement=True, logger=logger)
        plan.select_join_channel(0, now=1_000.0)
        logger.debug.assert_any_call("Selected channel %d", 868_100_000)

    def test_unavailable_channel_logged(self) -> None:
        import logging
        logger = MagicMock(spec=logging.Logger)
        plan = EU868ChannelPlan(duty_cycle_enforcement=True, logger=logger)
        plan.record_transmission(Channel(868_100_000, "SF7BW125"), 0.05, 1_000.0)

        with patch("lora_attack_toolkit.lorawan.channel_plan._time.sleep"):
            plan.select_join_channel(0, now=1_000.001)

        logger.debug.assert_any_call("Channel %d unavailable due to Duty Cycle", 868_100_000)

    def test_wait_logged_when_all_busy(self) -> None:
        import logging
        logger = MagicMock(spec=logging.Logger)
        plan = EU868ChannelPlan(duty_cycle_enforcement=True, logger=logger)
        for ch in plan.get_join_channels():
            plan.record_transmission(ch, 0.05, 1_000.0)

        with patch("lora_attack_toolkit.lorawan.channel_plan._time.sleep"):
            plan.select_join_channel(0, now=1_000.001)

        wait_calls = [
            call for call in logger.info.call_args_list
            if "Waiting" in str(call)
        ]
        self.assertTrue(len(wait_calls) >= 1)


class TestGetChannelPlanDutyCycle(unittest.TestCase):
    def test_eu868_duty_cycle_enforcement_true_by_default(self) -> None:
        plan = get_channel_plan("EU868")
        self.assertIsInstance(plan, EU868ChannelPlan)
        self.assertTrue(plan._duty_cycle_enforcement)

    def test_eu868_duty_cycle_enforcement_can_be_disabled(self) -> None:
        plan = get_channel_plan("EU868", duty_cycle_enforcement=False)
        self.assertIsInstance(plan, EU868ChannelPlan)
        self.assertFalse(plan._duty_cycle_enforcement)

    def test_passthrough_duty_cycle_not_supported(self) -> None:
        plan = get_channel_plan("US915", duty_cycle_enforcement=True)
        self.assertFalse(plan.supports_duty_cycle())


if __name__ == "__main__":
    unittest.main()
