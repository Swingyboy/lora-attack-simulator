"""Tests for validated downlink processing."""

from __future__ import annotations

import struct
import unittest

from lora_attack_toolkit.lorawan.crypto import data_mic
from lora_attack_toolkit.runtime.device import SimulatedDevice
import pytest

pytestmark = pytest.mark.unit


def _make_device() -> SimulatedDevice:
    device = SimulatedDevice(
        dev_eui="0102030405060708",
        join_eui="0807060504030201",
        app_key="00" * 16,
    )
    device.runtime.joined = True
    device.runtime.dev_addr_le = bytes.fromhex("01020304")
    device.runtime.nwk_s_key = bytes(16)
    device.runtime.app_s_key = bytes(16)
    device.runtime.fcnt_up = 1
    device.runtime.fcnt_down = 0
    return device


def _build_valid_downlink(
    device: SimulatedDevice,
    fcnt_down: int,
    *,
    mic_fcnt_down: int | None = None,
    mtype: int = 3,
) -> bytes:
    mhdr = (mtype << 5) & 0xE0
    dev_addr_le = device.runtime.dev_addr_le
    fctrl = 0x00
    fcnt_bytes = struct.pack("<H", fcnt_down & 0xFFFF)
    frame_no_mic = bytes([mhdr]) + dev_addr_le + bytes([fctrl]) + fcnt_bytes
    mic = data_mic(
        nwk_s_key=device.runtime.nwk_s_key,
        msg=frame_no_mic,
        direction=1,
        dev_addr_le=dev_addr_le,
        fcnt_up=fcnt_down if mic_fcnt_down is None else mic_fcnt_down,
    )
    return frame_no_mic + mic


class TestProcessDownlinkDevAddr(unittest.TestCase):
    def test_wrong_devaddr_rejected(self) -> None:
        device = _make_device()
        frame = _build_valid_downlink(device, fcnt_down=1)
        wrong_frame = frame[:1] + bytes.fromhex("deadbeef") + frame[5:]

        result = device.process_downlink(wrong_frame)

        self.assertFalse(result.accepted)
        self.assertEqual(result.reject_reason, "devaddr_mismatch")
        self.assertFalse(result.dev_addr_match)

    def test_correct_devaddr_passes_check(self) -> None:
        device = _make_device()

        result = device.process_downlink(_build_valid_downlink(device, fcnt_down=1))

        self.assertTrue(result.dev_addr_match)

    def test_state_unchanged_after_wrong_devaddr(self) -> None:
        device = _make_device()
        original_fcnt = device.runtime.fcnt_down
        frame = _build_valid_downlink(device, fcnt_down=1)

        device.process_downlink(frame[:1] + bytes.fromhex("deadbeef") + frame[5:])

        self.assertEqual(device.runtime.fcnt_down, original_fcnt)


class TestProcessDownlinkMIC(unittest.TestCase):
    def test_corrupted_mic_rejected(self) -> None:
        device = _make_device()
        frame = _build_valid_downlink(device, fcnt_down=1)

        result = device.process_downlink(frame[:-4] + bytes(b ^ 0xFF for b in frame[-4:]))

        self.assertFalse(result.accepted)
        self.assertEqual(result.reject_reason, "invalid_mic")
        self.assertFalse(result.valid_mic)

    def test_valid_mic_passes(self) -> None:
        device = _make_device()

        result = device.process_downlink(_build_valid_downlink(device, fcnt_down=1))

        self.assertTrue(result.valid_mic)

    def test_state_unchanged_after_bad_mic(self) -> None:
        device = _make_device()
        original_fcnt = device.runtime.fcnt_down
        frame = _build_valid_downlink(device, fcnt_down=1)

        device.process_downlink(frame[:-4] + bytes(b ^ 0xFF for b in frame[-4:]))

        self.assertEqual(device.runtime.fcnt_down, original_fcnt)


class TestProcessDownlinkFCntDown(unittest.TestCase):
    def test_fresh_fcnt_accepted(self) -> None:
        device = _make_device()
        device.runtime.fcnt_down = 5

        result = device.process_downlink(_build_valid_downlink(device, fcnt_down=6))

        self.assertTrue(result.fcnt_ok)
        self.assertTrue(result.accepted)
        self.assertEqual(device.runtime.fcnt_down, 6)

    def test_stale_fcnt_rejected(self) -> None:
        device = _make_device()
        device.runtime.fcnt_down = 0x00010005

        result = device.process_downlink(
            _build_valid_downlink(device, fcnt_down=5, mic_fcnt_down=0x00010005)
        )

        self.assertFalse(result.accepted)
        self.assertFalse(result.fcnt_ok)
        self.assertIn("stale_fcnt", result.reject_reason or "")

    def test_equal_fcnt_rejected(self) -> None:
        device = _make_device()
        device.runtime.fcnt_down = 7

        result = device.process_downlink(_build_valid_downlink(device, fcnt_down=7))

        self.assertFalse(result.accepted)
        self.assertFalse(result.fcnt_ok)


class TestProcessDownlinkMType(unittest.TestCase):
    def test_unconfirmed_data_down_accepted(self) -> None:
        device = _make_device()

        result = device.process_downlink(_build_valid_downlink(device, fcnt_down=1, mtype=3))

        self.assertEqual(result.mtype, 3)
        self.assertTrue(result.accepted)

    def test_confirmed_data_down_accepted(self) -> None:
        device = _make_device()

        result = device.process_downlink(_build_valid_downlink(device, fcnt_down=1, mtype=5))

        self.assertEqual(result.mtype, 5)
        self.assertTrue(result.accepted)

    def test_join_accept_mtype_rejected(self) -> None:
        device = _make_device()

        result = device.process_downlink(_build_valid_downlink(device, fcnt_down=1, mtype=1))

        self.assertFalse(result.accepted)
        self.assertIn("unsupported_mtype", result.reject_reason or "")

    def test_uplink_mtype_rejected(self) -> None:
        device = _make_device()

        result = device.process_downlink(_build_valid_downlink(device, fcnt_down=1, mtype=0))

        self.assertFalse(result.accepted)
        self.assertIn("unsupported_mtype", result.reject_reason or "")

    def test_state_unchanged_after_bad_mtype(self) -> None:
        device = _make_device()
        original_fcnt = device.runtime.fcnt_down

        device.process_downlink(_build_valid_downlink(device, fcnt_down=1, mtype=1))

        self.assertEqual(device.runtime.fcnt_down, original_fcnt)


class TestProcessDownlinkMinLength(unittest.TestCase):
    def test_too_short_rejected(self) -> None:
        device = _make_device()

        result = device.process_downlink(b"\x60\x01\x02\x03")

        self.assertFalse(result.accepted)
        self.assertIn("frame_too_short", result.reject_reason or "")

    def test_empty_frame_rejected(self) -> None:
        device = _make_device()

        result = device.process_downlink(b"")

        self.assertFalse(result.accepted)
        self.assertIn("frame_too_short", result.reject_reason or "")


class TestProcessDownlinkValidResult(unittest.TestCase):
    def test_valid_frame_all_fields_true(self) -> None:
        device = _make_device()

        result = device.process_downlink(_build_valid_downlink(device, fcnt_down=1, mtype=3))

        self.assertTrue(result.accepted)
        self.assertIsNone(result.reject_reason)
        self.assertTrue(result.dev_addr_match)
        self.assertTrue(result.valid_mic)
        self.assertTrue(result.fcnt_ok)
        self.assertEqual(result.mtype, 3)
        self.assertEqual(result.fcnt_32, 1)


if __name__ == "__main__":
    unittest.main()
