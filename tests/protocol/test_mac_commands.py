"""Tests for MAC command utilities."""

from __future__ import annotations

import unittest

import pytest

from lora_attack_toolkit.lorawan.mac_commands import (
    CID_DEV_STATUS_REQ,
    CID_DUTY_CYCLE_REQ,
    CID_LINK_ADR_REQ,
    CID_NEW_CHANNEL_REQ,
    CID_RX_PARAM_SETUP_REQ,
    CID_RX_TIMING_SETUP_REQ,
    build_dev_status_req,
    build_duty_cycle_req,
    build_link_adr_req,
    build_malformed_mac_command,
    build_new_channel_req,
    build_rx_param_setup_req,
    build_rx_timing_setup_req,
    encode_mac_commands,
    parse_mac_command,
)

pytestmark = pytest.mark.unit


class TestMACCommandBuilders(unittest.TestCase):
    """Test MAC command builder functions."""

    def test_build_link_adr_req(self) -> None:
        """Test LinkADRReq MAC command building."""
        cmd = build_link_adr_req(data_rate=5, tx_power=2, ch_mask=0x00FF, redundancy=1)

        self.assertEqual(cmd.cid, CID_LINK_ADR_REQ)
        self.assertEqual(len(cmd.payload), 4)

        # Check data rate and TX power encoding
        self.assertEqual(cmd.payload[0], (5 << 4) | 2)  # DR=5, TXPower=2

        # Check channel mask (little-endian)
        self.assertEqual(cmd.payload[1], 0xFF)
        self.assertEqual(cmd.payload[2], 0x00)

        # Check redundancy
        self.assertEqual(cmd.payload[3], 1)

    def test_build_rx_param_setup_req(self) -> None:
        """Test RXParamSetupReq MAC command building."""
        cmd = build_rx_param_setup_req(
            rx1_dr_offset=2,
            rx2_data_rate=3,
            frequency=869525000,
        )

        self.assertEqual(cmd.cid, CID_RX_PARAM_SETUP_REQ)
        self.assertEqual(len(cmd.payload), 4)

        # Check DL settings encoding
        self.assertEqual(cmd.payload[0], (2 << 4) | 3)  # RX1DROffset=2, RX2DataRate=3

        # Check frequency encoding (in 100 Hz units)
        freq_100hz = 869525000 // 100
        self.assertEqual(
            int.from_bytes(cmd.payload[1:4], byteorder="little"),
            freq_100hz,
        )

    def test_build_new_channel_req(self) -> None:
        """Test NewChannelReq MAC command building."""
        cmd = build_new_channel_req(
            ch_index=3,
            frequency=867100000,
            max_dr=5,
            min_dr=0,
        )

        self.assertEqual(cmd.cid, CID_NEW_CHANNEL_REQ)
        self.assertEqual(len(cmd.payload), 5)

        # Check channel index
        self.assertEqual(cmd.payload[0], 3)

        # Check frequency encoding
        freq_100hz = 867100000 // 100
        self.assertEqual(
            int.from_bytes(cmd.payload[1:4], byteorder="little"),
            freq_100hz,
        )

        # Check DR range encoding
        self.assertEqual(cmd.payload[4], (5 << 4) | 0)  # MaxDR=5, MinDR=0

    def test_build_dev_status_req(self) -> None:
        """Test DevStatusReq MAC command building."""
        cmd = build_dev_status_req()

        self.assertEqual(cmd.cid, CID_DEV_STATUS_REQ)
        self.assertEqual(len(cmd.payload), 0)

    def test_build_duty_cycle_req(self) -> None:
        """Test DutyCycleReq MAC command building."""
        cmd = build_duty_cycle_req(max_duty_cycle=4)

        self.assertEqual(cmd.cid, CID_DUTY_CYCLE_REQ)
        self.assertEqual(len(cmd.payload), 1)
        self.assertEqual(cmd.payload[0], 4)

    def test_build_rx_timing_setup_req(self) -> None:
        """Test RXTimingSetupReq MAC command building."""
        cmd = build_rx_timing_setup_req(delay=5)

        self.assertEqual(cmd.cid, CID_RX_TIMING_SETUP_REQ)
        self.assertEqual(len(cmd.payload), 1)
        self.assertEqual(cmd.payload[0], 5)


class TestMalformedMACCommands(unittest.TestCase):
    """Test malformed MAC command generation."""

    def test_build_malformed_truncated(self) -> None:
        """Test building truncated malformed MAC command."""
        cmd = build_malformed_mac_command(
            cid=CID_LINK_ADR_REQ,
            malformation_type="truncated",
        )

        self.assertEqual(cmd.cid, CID_LINK_ADR_REQ)
        # LinkADRReq expects 4 bytes, truncated should be less
        self.assertLess(len(cmd.payload), 4)

    def test_build_malformed_oversized(self) -> None:
        """Test building oversized malformed MAC command."""
        cmd = build_malformed_mac_command(
            cid=CID_LINK_ADR_REQ,
            malformation_type="oversized",
        )

        self.assertEqual(cmd.cid, CID_LINK_ADR_REQ)
        # LinkADRReq expects 4 bytes, oversized should be more
        self.assertGreater(len(cmd.payload), 4)

    def test_build_malformed_invalid_values(self) -> None:
        """Test building malformed MAC command with invalid values."""
        cmd = build_malformed_mac_command(
            cid=CID_LINK_ADR_REQ,
            malformation_type="invalid_values",
        )

        self.assertEqual(cmd.cid, CID_LINK_ADR_REQ)
        # Should have correct length but invalid parameter values
        self.assertEqual(len(cmd.payload), 4)

    def test_build_malformed_corrupted(self) -> None:
        """Test building corrupted malformed MAC command."""
        cmd = build_malformed_mac_command(
            cid=CID_NEW_CHANNEL_REQ,
            malformation_type="corrupted",
            length=5,
        )

        self.assertEqual(cmd.cid, CID_NEW_CHANNEL_REQ)
        self.assertEqual(len(cmd.payload), 5)

    def test_build_malformed_dev_status_oversized(self) -> None:
        """Test oversized DevStatusReq (expects 0 bytes)."""
        cmd = build_malformed_mac_command(
            cid=CID_DEV_STATUS_REQ,
            malformation_type="oversized",
        )

        self.assertEqual(cmd.cid, CID_DEV_STATUS_REQ)
        # DevStatusReq expects 0 bytes, oversized should have payload
        self.assertGreater(len(cmd.payload), 0)


class TestMACCommandEncoding(unittest.TestCase):
    """Test MAC command encoding and parsing."""

    def test_mac_command_to_bytes(self) -> None:
        """Test MACCommand.to_bytes() method."""
        cmd = build_link_adr_req(data_rate=3, tx_power=1, ch_mask=0xFF00, redundancy=2)

        cmd_bytes = cmd.to_bytes()

        # Should be CID + payload
        self.assertEqual(len(cmd_bytes), 1 + 4)
        self.assertEqual(cmd_bytes[0], CID_LINK_ADR_REQ)

    def test_encode_multiple_mac_commands(self) -> None:
        """Test encoding multiple MAC commands."""
        cmd1 = build_link_adr_req()
        cmd2 = build_dev_status_req()

        encoded = encode_mac_commands([cmd1, cmd2])

        # Should be cmd1 (5 bytes) + cmd2 (1 byte) = 6 bytes
        self.assertEqual(len(encoded), 5 + 1)

    def test_parse_link_adr_req(self) -> None:
        """Test parsing LinkADRReq MAC command."""
        cmd = build_link_adr_req(data_rate=5, tx_power=2)
        cmd_bytes = cmd.to_bytes()

        parsed, consumed = parse_mac_command(cmd_bytes)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.cid, CID_LINK_ADR_REQ)
        self.assertEqual(len(parsed.payload), 4)
        self.assertEqual(consumed, 5)

    def test_parse_dev_status_req(self) -> None:
        """Test parsing DevStatusReq MAC command."""
        cmd = build_dev_status_req()
        cmd_bytes = cmd.to_bytes()

        parsed, consumed = parse_mac_command(cmd_bytes)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.cid, CID_DEV_STATUS_REQ)
        self.assertEqual(len(parsed.payload), 0)
        self.assertEqual(consumed, 1)

    def test_parse_truncated_command(self) -> None:
        """Test parsing truncated MAC command."""
        # LinkADRReq with only 2 bytes of payload (expects 4)
        truncated = bytes([CID_LINK_ADR_REQ, 0x00, 0x00])

        parsed, consumed = parse_mac_command(truncated)

        # Should return None for truncated command
        self.assertIsNone(parsed)
        self.assertEqual(consumed, len(truncated))

    def test_parse_empty_data(self) -> None:
        """Test parsing empty data."""
        parsed, consumed = parse_mac_command(b"")

        self.assertIsNone(parsed)
        self.assertEqual(consumed, 0)

    def test_parse_unknown_cid_stops(self) -> None:
        """Unknown CID yields one opaque command and consumes the rest (parsing stops)."""
        data = bytes([0xFF, 0x01, 0x02])

        parsed, consumed = parse_mac_command(data)

        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertTrue(parsed.is_unknown)
        self.assertEqual(parsed.cid, 0xFF)
        self.assertEqual(parsed.payload, bytes([0x01, 0x02]))
        # Everything consumed → a caller loop terminates without misparsing 0x01/0x02.
        self.assertEqual(consumed, len(data))


if __name__ == "__main__":
    unittest.main()
