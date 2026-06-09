"""Tests for the Radio abstraction and EU868RegionProfile."""

from __future__ import annotations

import unittest

from lora_attack_toolkit.lorawan.radio import EU868RegionProfile
from lora_attack_toolkit.lorawan.radio import Radio


EU868_BASE = [868_100_000, 868_300_000, 868_500_000]


def _make_radio() -> Radio:
    return Radio(EU868RegionProfile())


def _cflist(freqs_hz: list[int], cflist_type: int = 0) -> bytes:
    data = bytearray(16)
    for i, f in enumerate(freqs_hz[:5]):
        raw = (f // 100).to_bytes(3, "little")
        data[i * 3 : i * 3 + 3] = raw
    data[15] = cflist_type
    return bytes(data)


# ─── Region profile ───────────────────────────────────────────────────────────


class TestEU868RegionProfile(unittest.TestCase):
    def test_base_channels(self) -> None:
        self.assertEqual(EU868RegionProfile.BASE_UPLINK_CHANNELS_HZ, EU868_BASE)

    def test_freq_range(self) -> None:
        self.assertLess(EU868RegionProfile.FREQ_MIN_HZ, EU868RegionProfile.FREQ_MAX_HZ)

    def test_defaults(self) -> None:
        self.assertIsInstance(EU868RegionProfile.DEFAULT_DATA_RATE, str)
        self.assertIsInstance(EU868RegionProfile.DEFAULT_TX_POWER, int)


# ─── Radio — initial state ────────────────────────────────────────────────────


class TestRadioInitialState(unittest.TestCase):
    def test_active_channels_equal_base_initially(self) -> None:
        radio = _make_radio()
        self.assertEqual(radio.get_active_uplink_channels(), EU868_BASE)

    def test_data_rate_is_region_default(self) -> None:
        radio = _make_radio()
        self.assertEqual(radio.get_current_data_rate(), EU868RegionProfile.DEFAULT_DATA_RATE)

    def test_tx_power_is_region_default(self) -> None:
        radio = _make_radio()
        self.assertEqual(radio.get_current_tx_power(), EU868RegionProfile.DEFAULT_TX_POWER)

    def test_region_name(self) -> None:
        radio = _make_radio()
        self.assertEqual(radio.region_name, "EU868")


# ─── Radio — CFList application ───────────────────────────────────────────────


class TestRadioCFList(unittest.TestCase):
    def test_cflist_adds_channels(self) -> None:
        radio = _make_radio()
        radio.apply_cflist(_cflist([867_100_000, 867_300_000]))
        active = radio.get_active_uplink_channels()
        self.assertIn(867_100_000, active)
        self.assertIn(867_300_000, active)

    def test_base_channels_always_preserved(self) -> None:
        radio = _make_radio()
        radio.apply_cflist(_cflist([867_100_000]))
        for ch in EU868_BASE:
            self.assertIn(ch, radio.get_active_uplink_channels())

    def test_cflist_replaces_previous_cflist(self) -> None:
        """Applying CFList B must remove CFList A channels — no accumulation."""
        radio = _make_radio()
        radio.apply_cflist(_cflist([867_100_000, 867_300_000]))
        radio.apply_cflist(_cflist([867_500_000, 867_700_000]))
        active = radio.get_active_uplink_channels()
        # CFList A channels must be gone
        self.assertNotIn(867_100_000, active)
        self.assertNotIn(867_300_000, active)
        # CFList B channels must be present
        self.assertIn(867_500_000, active)
        self.assertIn(867_700_000, active)

    def test_no_infinite_growth(self) -> None:
        """Repeated CFList applications must not grow the channel list indefinitely."""
        radio = _make_radio()
        for seed in range(10):
            freqs = [867_100_000 + seed * 200_000]
            radio.apply_cflist(_cflist(freqs))
        # EU868 base (3) + at most 5 CFList slots → never more than 8
        self.assertLessEqual(len(radio.get_active_uplink_channels()), 8)

    def test_cflist_deduplicates_within_list(self) -> None:
        radio = _make_radio()
        radio.apply_cflist(_cflist([867_100_000, 867_100_000, 867_100_000]))
        active = radio.get_active_uplink_channels()
        self.assertEqual(active.count(867_100_000), 1)

    def test_base_channel_in_cflist_not_duplicated(self) -> None:
        radio = _make_radio()
        radio.apply_cflist(_cflist([868_100_000, 867_100_000]))
        active = radio.get_active_uplink_channels()
        self.assertEqual(active.count(868_100_000), 1)

    def test_full_5_channel_cflist(self) -> None:
        radio = _make_radio()
        new_freqs = [867_100_000, 867_300_000, 867_500_000, 867_700_000, 867_900_000]
        radio.apply_cflist(_cflist(new_freqs))
        active = radio.get_active_uplink_channels()
        for f in new_freqs:
            self.assertIn(f, active)
        self.assertEqual(len(active), len(EU868_BASE) + 5)

    def test_zero_slots_ignored(self) -> None:
        radio = _make_radio()
        radio.apply_cflist(_cflist([867_100_000, 0, 0]))
        active = radio.get_active_uplink_channels()
        self.assertNotIn(0, active)

    def test_out_of_range_freq_ignored(self) -> None:
        """Frequencies outside EU868 range must be silently ignored."""
        radio = _make_radio()
        radio.apply_cflist(_cflist([920_000_000]))  # US915 range
        self.assertEqual(radio.get_active_uplink_channels(), EU868_BASE)


# ─── Radio — invalid CFList (no mutation) ────────────────────────────────────


class TestRadioInvalidCFList(unittest.TestCase):
    def _unchanged(self, cflist_bytes: bytes | None) -> None:
        radio = _make_radio()
        before = radio.get_active_uplink_channels()
        radio.apply_cflist(cflist_bytes)
        after = radio.get_active_uplink_channels()
        self.assertEqual(before, after, msg=f"radio state mutated for cflist={cflist_bytes!r}")

    def test_none_cflist_is_noop(self) -> None:
        self._unchanged(None)

    def test_empty_bytes_is_noop(self) -> None:
        self._unchanged(b"")

    def test_wrong_length_is_noop(self) -> None:
        self._unchanged(b"\x00" * 10)
        self._unchanged(b"\x00" * 15)
        self._unchanged(b"\x00" * 17)

    def test_cflist_type_1_is_noop(self) -> None:
        self._unchanged(_cflist([867_100_000], cflist_type=1))

    def test_cflist_type_255_is_noop(self) -> None:
        self._unchanged(_cflist([867_100_000], cflist_type=255))

    def test_after_invalid_cflist_previous_cflist_preserved(self) -> None:
        """Invalid CFList must not clear previously applied CFList channels."""
        radio = _make_radio()
        radio.apply_cflist(_cflist([867_100_000]))
        radio.apply_cflist(None)  # invalid — must not clear
        self.assertIn(867_100_000, radio.get_active_uplink_channels())


# ─── Radio — channel selection ────────────────────────────────────────────────


class TestRadioChannelSelection(unittest.TestCase):
    def test_round_robin_base_channels(self) -> None:
        radio = _make_radio()
        selected = [radio.get_next_uplink_channel() for _ in range(6)]
        expected = EU868_BASE + EU868_BASE
        self.assertEqual(selected, expected)

    def test_round_robin_after_cflist(self) -> None:
        radio = _make_radio()
        radio.apply_cflist(_cflist([867_100_000]))
        # 4 active channels: base (3) + cflist (1)
        all_channels = EU868_BASE + [867_100_000]
        selected = [radio.get_next_uplink_channel() for _ in range(8)]
        for ch in all_channels:
            self.assertIn(ch, selected)

    def test_round_robin_wraps(self) -> None:
        radio = _make_radio()
        n = len(EU868_BASE)
        # Go round twice
        for _ in range(n):
            radio.get_next_uplink_channel()
        # Should start from beginning again
        first_again = radio.get_next_uplink_channel()
        self.assertEqual(first_again, EU868_BASE[0])


# ─── EU868ChannelPlan — CFList accumulation fix ───────────────────────────────


class TestEU868ChannelPlanCFListFix(unittest.TestCase):
    """Verify the same replacement semantics in EU868ChannelPlan itself."""

    def _plan(self):
        from lora_attack_toolkit.lorawan.channel_plan import EU868ChannelPlan
        return EU868ChannelPlan()

    def _cflist(self, freqs: list[int]) -> bytes:
        return _cflist(freqs)

    def test_cflist_replaces_previous(self) -> None:
        plan = self._plan()
        plan.apply_cflist(self._cflist([867_100_000]))
        plan.apply_cflist(self._cflist([867_300_000]))
        freqs = [c.frequency_hz for c in plan.get_uplink_channels()]
        self.assertNotIn(867_100_000, freqs)
        self.assertIn(867_300_000, freqs)

    def test_base_channels_preserved(self) -> None:
        plan = self._plan()
        plan.apply_cflist(self._cflist([867_100_000]))
        freqs = [c.frequency_hz for c in plan.get_uplink_channels()]
        for ch in EU868_BASE:
            self.assertIn(ch, freqs)

    def test_no_infinite_growth(self) -> None:
        plan = self._plan()
        for seed in range(10):
            plan.apply_cflist(self._cflist([867_100_000 + seed * 200_000]))
        self.assertLessEqual(len(plan.get_uplink_channels()), 8)


# ─── Integration — device apply_join_accept updates Radio ────────────────────


class TestDeviceRadioIntegration(unittest.TestCase):
    def _make_device(self) -> object:
        from lora_attack_toolkit.device.model import SimulatedDevice
        from lora_attack_toolkit.lorawan.radio import EU868RegionProfile, Radio

        device = SimulatedDevice(
            dev_eui="0011223344556677",
            join_eui="0102030405060708",
            app_key="000102030405060708090a0b0c0d0e0f",
        )
        device.runtime.radio = Radio(EU868RegionProfile())
        return device

    def test_repeated_join_accept_does_not_grow_channel_list(self) -> None:
        """Applying JoinAccept with different CFLists must never grow channels unboundedly."""
        from unittest.mock import MagicMock, patch
        from lora_attack_toolkit.lorawan.protocol.frames import JoinAcceptData

        device = self._make_device()

        def make_fake_parsed(cflist_bytes):
            p = MagicMock(spec=JoinAcceptData)
            p.app_nonce = b"\x00\x00\x00"
            p.net_id = b"\x00\x00\x00"
            p.dev_addr_le = b"\x01\x02\x03\x04"
            p.cflist = cflist_bytes
            return p

        with patch("lora_attack_toolkit.device.model.decode_join_accept") as mock_dec, \
             patch("lora_attack_toolkit.device.model.derive_session_keys", return_value=(b"\x00" * 16, b"\x00" * 16)):
            # Simulate 5 JoinAccepts with different CFLists
            for seed in range(5):
                freq = 867_100_000 + seed * 200_000
                cflist_bytes = _cflist([freq])
                device.runtime.dev_nonce = b"\x00\x01"
                mock_dec.return_value = make_fake_parsed(cflist_bytes)
                device.apply_join_accept(b"\xff" * 17)

        active = device.runtime.radio.get_active_uplink_channels()
        self.assertLessEqual(len(active), 8, "channel list grew unboundedly")
        # Base channels must always be present
        for ch in EU868_BASE:
            self.assertIn(ch, active)
