"""Tests for downlink validation (SimulatedDevice.validate_downlink).

Verifies that invalid frames cannot mutate device state:
- wrong DevAddr
- invalid MIC
- stale FCntDown
- unsupported MType

Acceptance criteria from P0:
- Invalid MIC, wrong DevAddr, stale counter, and unsupported MType cannot
  change state.
- Tests verify state remains unchanged after rejection.
"""

from __future__ import annotations

import struct
import unittest

from lora_attack_toolkit.runtime.device import SimulatedDevice
from lora_attack_toolkit.lorawan.crypto import data_mic


def _make_device() -> SimulatedDevice:
    """Return a device with a known joined session."""
    device = SimulatedDevice(
        dev_eui="0102030405060708",
        join_eui="0807060504030201",
        app_key="00" * 16,
    )
    # Manually inject a joined session
    device.runtime.joined = True
    device.runtime.dev_addr_le = bytes.fromhex("01020304")
    device.runtime.nwk_s_key = bytes(16)  # all-zero key for test frames
    device.runtime.app_s_key = bytes(16)
    device.runtime.fcnt_up = 1
    device.runtime.fcnt_down = 0
    return device


def _build_valid_downlink(
    device: SimulatedDevice,
    fcnt_down: int,
    mtype: int = 3,  # UnconfirmedDataDown
) -> bytes:
    """Build a well-formed downlink with a valid MIC for the device's session."""
    # MHDR: (mtype << 5) | 0x00 (major=0)
    mhdr = (mtype << 5) & 0xE0
    dev_addr_le = device.runtime.dev_addr_le
    fctrl = 0x00
    fcnt_bytes = struct.pack("<H", fcnt_down & 0xFFFF)
    # No FOpts, no FPort, no payload — just headers + MIC
    frame_no_mic = bytes([mhdr]) + dev_addr_le + bytes([fctrl]) + fcnt_bytes
    mic = data_mic(
        nwk_s_key=device.runtime.nwk_s_key,
        msg=frame_no_mic,
        direction=1,
        dev_addr_le=dev_addr_le,
        fcnt_up=fcnt_down,
    )
    return frame_no_mic + mic


class TestValidateDownlinkDevAddr(unittest.TestCase):
    """Wrong DevAddr must be rejected without touching device state."""

    def test_wrong_devaddr_rejected(self) -> None:
        device = _make_device()
        # Build frame for a different DevAddr
        frame = _build_valid_downlink(device, fcnt_down=0)
        # Overwrite DevAddr in frame with a wrong one
        wrong_frame = frame[:1] + bytes.fromhex("deadbeef") + frame[5:]
        result = device.validate_downlink(wrong_frame)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reject_reason"], "devaddr_mismatch")
        self.assertFalse(result["dev_addr_match"])

    def test_correct_devaddr_passes_check(self) -> None:
        device = _make_device()
        frame = _build_valid_downlink(device, fcnt_down=0)
        result = device.validate_downlink(frame)
        self.assertTrue(result["dev_addr_match"])

    def test_state_unchanged_after_wrong_devaddr(self) -> None:
        device = _make_device()
        original_fcnt = device.runtime.fcnt_down
        frame = _build_valid_downlink(device, fcnt_down=0)
        wrong_frame = frame[:1] + bytes.fromhex("deadbeef") + frame[5:]
        device.validate_downlink(wrong_frame)
        self.assertEqual(device.runtime.fcnt_down, original_fcnt)


class TestValidateDownlinkMIC(unittest.TestCase):
    """Invalid MIC must be rejected before applying any commands."""

    def test_corrupted_mic_rejected(self) -> None:
        device = _make_device()
        frame = _build_valid_downlink(device, fcnt_down=0)
        # Flip all MIC bytes
        corrupted = frame[:-4] + bytes(b ^ 0xFF for b in frame[-4:])
        result = device.validate_downlink(corrupted)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reject_reason"], "invalid_mic")
        self.assertFalse(result["valid_mic"])

    def test_valid_mic_passes(self) -> None:
        device = _make_device()
        frame = _build_valid_downlink(device, fcnt_down=0)
        result = device.validate_downlink(frame)
        self.assertTrue(result["valid_mic"])

    def test_state_unchanged_after_bad_mic(self) -> None:
        device = _make_device()
        original_fcnt = device.runtime.fcnt_down
        frame = _build_valid_downlink(device, fcnt_down=0)
        corrupted = frame[:-4] + bytes(b ^ 0xFF for b in frame[-4:])
        device.validate_downlink(corrupted)
        self.assertEqual(device.runtime.fcnt_down, original_fcnt)


class TestValidateDownlinkFCntDown(unittest.TestCase):
    """Stale FCntDown must be rejected."""

    def test_fresh_fcnt_accepted(self) -> None:
        device = _make_device()
        device.runtime.fcnt_down = 5
        frame = _build_valid_downlink(device, fcnt_down=5)
        result = device.validate_downlink(frame)
        self.assertTrue(result["fcnt_ok"])
        self.assertTrue(result["valid"])

    def test_stale_fcnt_rejected(self) -> None:
        device = _make_device()
        device.runtime.fcnt_down = 10
        # Build frame with fcnt=5 (< 10 → stale)
        frame = _build_valid_downlink(device, fcnt_down=5)
        result = device.validate_downlink(frame)
        self.assertFalse(result["valid"])
        self.assertFalse(result["fcnt_ok"])
        self.assertIn("stale_fcnt", result["reject_reason"])

    def test_equal_fcnt_accepted(self) -> None:
        """FCntDown equal to expected is accepted (not stale)."""
        device = _make_device()
        device.runtime.fcnt_down = 7
        frame = _build_valid_downlink(device, fcnt_down=7)
        result = device.validate_downlink(frame)
        self.assertTrue(result["fcnt_ok"])
        self.assertTrue(result["valid"])


class TestValidateDownlinkMType(unittest.TestCase):
    """Unsupported MType must be rejected."""

    def test_unconfirmed_data_down_accepted(self) -> None:
        device = _make_device()
        frame = _build_valid_downlink(device, fcnt_down=0, mtype=3)  # UnconfirmedDataDown
        result = device.validate_downlink(frame)
        self.assertEqual(result["mtype"], 3)
        self.assertTrue(result["valid"])

    def test_confirmed_data_down_accepted(self) -> None:
        device = _make_device()
        frame = _build_valid_downlink(device, fcnt_down=0, mtype=5)  # ConfirmedDataDown
        result = device.validate_downlink(frame)
        self.assertEqual(result["mtype"], 5)
        self.assertTrue(result["valid"])

    def test_join_accept_mtype_rejected(self) -> None:
        device = _make_device()
        # MType 1 = JoinAccept
        frame = _build_valid_downlink(device, fcnt_down=0, mtype=1)
        result = device.validate_downlink(frame)
        self.assertFalse(result["valid"])
        self.assertIn("unsupported_mtype", result["reject_reason"])

    def test_uplink_mtype_rejected(self) -> None:
        device = _make_device()
        # MType 0 = UnconfirmedDataUp
        frame = _build_valid_downlink(device, fcnt_down=0, mtype=0)
        result = device.validate_downlink(frame)
        self.assertFalse(result["valid"])
        self.assertIn("unsupported_mtype", result["reject_reason"])

    def test_state_unchanged_after_bad_mtype(self) -> None:
        device = _make_device()
        original_fcnt = device.runtime.fcnt_down
        frame = _build_valid_downlink(device, fcnt_down=0, mtype=1)
        device.validate_downlink(frame)
        self.assertEqual(device.runtime.fcnt_down, original_fcnt)


class TestValidateDownlinkMinLength(unittest.TestCase):
    """Frames shorter than the minimum must be rejected."""

    def test_too_short_rejected(self) -> None:
        device = _make_device()
        result = device.validate_downlink(b"\x60\x01\x02\x03")
        self.assertFalse(result["valid"])
        self.assertIn("frame_too_short", result["reject_reason"])

    def test_empty_frame_rejected(self) -> None:
        device = _make_device()
        result = device.validate_downlink(b"")
        self.assertFalse(result["valid"])
        self.assertIn("frame_too_short", result["reject_reason"])


class TestValidateDownlinkValidResult(unittest.TestCase):
    """A fully valid frame returns valid=True with all check fields True."""

    def test_valid_frame_all_fields_true(self) -> None:
        device = _make_device()
        device.runtime.fcnt_down = 0
        frame = _build_valid_downlink(device, fcnt_down=0, mtype=3)
        result = device.validate_downlink(frame)

        self.assertTrue(result["valid"])
        self.assertIsNone(result["reject_reason"])
        self.assertTrue(result["dev_addr_match"])
        self.assertTrue(result["valid_mic"])
        self.assertTrue(result["fcnt_ok"])
        self.assertEqual(result["mtype"], 3)
        self.assertEqual(result["fcnt"], 0)


if __name__ == "__main__":
    unittest.main()
