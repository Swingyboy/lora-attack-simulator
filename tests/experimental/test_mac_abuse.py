"""Tests for MAC command abuse attack implementation."""

from __future__ import annotations

import unittest
from logging import getLogger
from unittest.mock import MagicMock

import pytest

from lora_attack_toolkit.attacks.context import AttackContext, AttackInput, AttackServices
from lora_attack_toolkit.attacks.packet_capture import PacketCapture
from lora_attack_toolkit.config import RadioMetadata
from lora_attack_toolkit.experimental.config import MACCommandConfigV1
from lora_attack_toolkit.experimental.mac_abuse import MACCommandAbuse, MACCommandAnalyzer
from lora_attack_toolkit.runtime.device import SimulatedDevice
from lora_attack_toolkit.runtime.gateway import GatewaySimulator

pytestmark = [pytest.mark.unit, pytest.mark.experimental]


class TestMACCommandAnalyzer(unittest.TestCase):
    """Test MACCommandAnalyzer functionality."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.analyzer = MACCommandAnalyzer()
        self.logger = getLogger("test")

    def test_analyze_no_mac_commands(self) -> None:
        """Test analysis when no MAC commands were injected."""
        capture = PacketCapture(self.logger)

        # Add some baseline uplinks
        capture.capture_uplink(
            phy_payload=b"\x40\x00\x00\x00\x00",
            packet_type="data_up",
            metadata={"phase": "setup"},
        )

        result = self.analyzer.analyze(capture)

        self.assertFalse(result["success"])
        self.assertIn("No MAC commands were injected", result["message"])

    def test_analyze_mac_command_injection(self) -> None:
        """Test analysis of MAC command injection."""
        capture = PacketCapture(self.logger)

        # Setup phase uplinks
        capture.capture_uplink(
            phy_payload=b"\x40\x00\x00\x00\x00",
            packet_type="data_up",
            metadata={"phase": "setup", "baseline": True},
        )

        # MAC command injection
        capture.capture_uplink(
            phy_payload=b"\x03\x52\xff\x00\x01",
            packet_type="mac_command",
            metadata={
                "phase": "execute",
                "mac_command_type": "LinkADRReq",
                "cid": 0x03,
            },
        )

        # Follow-up uplink after MAC command
        capture.capture_uplink(
            phy_payload=b"\x40\x00\x00\x00\x01",
            packet_type="data_up",
            metadata={"phase": "execute", "after_mac_command": True},
        )

        result = self.analyzer.analyze(capture)

        self.assertTrue(result["success"])
        self.assertIn("MAC command abuse executed", result["message"])
        self.assertEqual(result["metrics"]["mac_commands_injected"], 1)
        self.assertEqual(result["metrics"]["uplinks_after_attack"], 1)
        self.assertTrue(result["metrics"]["device_responded"])

    def test_analyze_malformed_mac_command(self) -> None:
        """Test analysis of malformed MAC command injection."""
        capture = PacketCapture(self.logger)

        # MAC command injection (malformed)
        capture.capture_uplink(
            phy_payload=b"\x03\x52\xff",  # Truncated LinkADRReq
            packet_type="mac_command",
            metadata={
                "phase": "execute",
                "mac_command_type": "LinkADRReq",
                "malformed": True,
                "malformation_type": "truncated",
            },
        )

        result = self.analyzer.analyze(capture)

        self.assertTrue(result["success"])
        self.assertIn("malformed command", result["message"])
        self.assertEqual(result["metrics"]["malformed_commands"], 1)

    def test_analyze_adr_state_changes(self) -> None:
        """Test analysis with ADR state tracking."""
        capture = PacketCapture(self.logger)

        # MAC command with ADR state change
        capture.capture_uplink(
            phy_payload=b"\x03\x52\xff\x00\x01",
            packet_type="mac_command",
            metadata={
                "phase": "execute",
                "mac_command_type": "LinkADRReq",
            },
        )

        # Uplink with ADR state
        capture.capture_uplink(
            phy_payload=b"\x40\x00\x00\x00\x01",
            packet_type="data_up",
            metadata={
                "phase": "execute",
                "adr_state": {"data_rate": 5, "tx_power": 2},
            },
        )

        result = self.analyzer.analyze(capture)

        self.assertTrue(result["success"])
        self.assertIn("ADR state change", result["message"])
        self.assertEqual(result["metrics"]["adr_state_changes"], 1)


class TestMACCommandAbuse(unittest.TestCase):
    """Test MACCommandAbuse attack class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.logger = getLogger("test")
        self.device = SimulatedDevice(
            dev_eui="0011223344556677",
            join_eui="0011223344556677",
            app_key="00112233445566770011223344556677",
        )

        self.gateway = MagicMock(spec=GatewaySimulator)

        self.radio = RadioMetadata(
            frequency=868100000,
            data_rate="SF7BW125",
            rssi=-60,
            snr=7.5,
        )
        self.attack_config = MACCommandConfigV1(
            command_type="LinkADRReq",
            malformed=False,
            parameters={"data_rate": 5, "tx_power": 2},
        )
        self.ctx = AttackContext(
            services=AttackServices(
                device=self.device,
                gateway=self.gateway,
                logger=self.logger,
                capture=PacketCapture(self.logger),
                metrics=None,
            ),
            input=AttackInput(
                typed_config=self.attack_config,
                expected_behavior=None,
                radio=self.radio,
                timeout_sec=30.0,
            ),
        )

    def test_mac_abuse_creation_link_adr(self) -> None:
        """Test MACCommandAbuse creation as a plugin."""
        attack = MACCommandAbuse()

        self.assertEqual(attack.name, "mac_command_injection")

    def test_mac_abuse_creation_malformed(self) -> None:
        """Test MACCommandAbuse uses typed context config."""
        self.ctx = AttackContext(
            services=self.ctx.services,
            input=AttackInput(
                typed_config=MACCommandConfigV1(
                    command_type="LinkADRReq",
                    malformed=True,
                    malformation_type="truncated",
                ),
                expected_behavior=None,
                radio=self.radio,
                timeout_sec=30.0,
            ),
        )

        self.assertTrue(self.ctx.config.malformed)
        self.assertEqual(self.ctx.config.malformation_type, "truncated")

    def test_build_legitimate_link_adr_req(self) -> None:
        """Test building legitimate LinkADRReq command."""
        attack = MACCommandAbuse()
        cmd = attack._build_legitimate_command(self.attack_config)

        self.assertEqual(cmd.cid, 0x03)  # LinkADRReq CID
        self.assertEqual(len(cmd.payload), 4)

    def test_build_legitimate_rx_param_setup_req(self) -> None:
        """Test building legitimate RXParamSetupReq command."""
        attack = MACCommandAbuse()
        cmd = attack._build_legitimate_command(
            MACCommandConfigV1(
                command_type="RXParamSetupReq",
                malformed=False,
                parameters={"rx2_data_rate": 3, "frequency": 869525000},
            )
        )

        self.assertEqual(cmd.cid, 0x05)  # RXParamSetupReq CID
        self.assertEqual(len(cmd.payload), 4)

    def test_build_malformed_command(self) -> None:
        """Test building malformed MAC command."""
        attack = MACCommandAbuse()
        cmd = attack._build_malformed_command(
            MACCommandConfigV1(
                command_type="LinkADRReq",
                malformed=True,
                malformation_type="truncated",
            )
        )

        self.assertEqual(cmd.cid, 0x03)  # LinkADRReq CID
        # Truncated should have less than 4 bytes
        self.assertLess(len(cmd.payload), 4)

    def test_adr_state_tracking(self) -> None:
        """Test ADR state tracking."""
        attack = MACCommandAbuse()
        adr_state = {"data_rate": 0, "tx_power": 0, "nb_trans": 1}
        cmd = attack._build_legitimate_command(
            MACCommandConfigV1(
                command_type="LinkADRReq",
                malformed=False,
                parameters={"data_rate": 5, "tx_power": 2, "redundancy": 1},
            )
        )

        attack._update_adr_state(cmd, adr_state)

        self.assertEqual(adr_state["data_rate"], cmd.payload[0] >> 4)
        self.assertEqual(adr_state["tx_power"], cmd.payload[0] & 0x0F)


if __name__ == "__main__":
    unittest.main()
