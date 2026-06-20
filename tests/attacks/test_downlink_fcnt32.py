"""Tests for 32-bit FCntDown reconstruction in process_downlink."""

from __future__ import annotations

import struct
import unittest

import pytest

from lora_attack_toolkit.lorawan.crypto import data_mic
from lora_attack_toolkit.runtime.device import SimulatedDevice

pytestmark = pytest.mark.unit


def _make_device() -> SimulatedDevice:
    device = SimulatedDevice(
        dev_eui="0102030405060708",
        join_eui="0807060504030201",
        app_key="11" * 16,
    )
    device.runtime.joined = True
    device.runtime.dev_addr_le = bytes.fromhex("04030201")
    device.runtime.nwk_s_key = bytes.fromhex("22" * 16)
    device.runtime.app_s_key = bytes.fromhex("33" * 16)
    return device


def _build_downlink(device: SimulatedDevice, wire_fcnt: int, mic_fcnt: int) -> bytes:
    mhdr = 0x60
    frame_no_mic = (
        bytes([mhdr])
        + device.runtime.dev_addr_le
        + bytes([0x00])
        + struct.pack("<H", wire_fcnt & 0xFFFF)
    )
    mic = data_mic(
        nwk_s_key=device.runtime.nwk_s_key,
        msg=frame_no_mic,
        direction=1,
        dev_addr_le=device.runtime.dev_addr_le,
        fcnt_up=mic_fcnt,
    )
    return frame_no_mic + mic


class TestDownlinkFCnt32(unittest.TestCase):
    def test_rollover_reconstructs_full_counter(self) -> None:
        device = _make_device()
        device.runtime.fcnt_down = 0x0000FFFE

        result = device.process_downlink(
            _build_downlink(device, wire_fcnt=0x0001, mic_fcnt=0x00010001)
        )

        self.assertTrue(result.accepted)
        self.assertEqual(result.fcnt_32, 0x00010001)
        self.assertEqual(device.runtime.fcnt_down, 0x00010001)

    def test_equal_reconstructed_counter_is_rejected_as_stale(self) -> None:
        device = _make_device()
        device.runtime.fcnt_down = 0x00010005

        result = device.process_downlink(
            _build_downlink(device, wire_fcnt=0x0005, mic_fcnt=0x00010005)
        )

        self.assertFalse(result.accepted)
        self.assertFalse(result.fcnt_ok)
        self.assertIn("stale_fcnt", result.reject_reason or "")
        self.assertEqual(device.runtime.fcnt_down, 0x00010005)

    def test_mic_uses_reconstructed_32bit_counter(self) -> None:
        device = _make_device()
        device.runtime.fcnt_down = 0x0000FFFE
        frame = _build_downlink(device, wire_fcnt=0x0001, mic_fcnt=0x00000001)

        result = device.process_downlink(frame)

        self.assertFalse(result.accepted)
        self.assertEqual(result.reject_reason, "invalid_mic")
        self.assertEqual(result.fcnt_32, 0x00010001)
        self.assertEqual(device.runtime.fcnt_down, 0x0000FFFE)


if __name__ == "__main__":
    unittest.main()
