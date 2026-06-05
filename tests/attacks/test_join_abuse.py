"""Tests for join abuse attack implementation."""

from __future__ import annotations

import unittest
from logging import getLogger
from unittest.mock import MagicMock

from lora_attack_toolkit.attacks.context import AttackContext, AttackInput, AttackServices
from lora_attack_toolkit.attacks.builtin.join_abuse import JoinAbuseAnalyzer, JoinAbuseAttack, VirtualDevice
from lora_attack_toolkit.attacks.packet_capture import PacketCapture
from lora_attack_toolkit.device.model import SimulatedDevice
from lora_attack_toolkit.gateway.model import GatewaySimulator
from lora_attack_toolkit.core.schema import RadioMetadata
from lora_attack_toolkit.core.schema_v1 import JoinFloodConfigV1


class TestJoinAbuseAnalyzer(unittest.TestCase):
    """Test JoinAbuseAnalyzer functionality."""
    
    def setUp(self) -> None:
        """Set up test fixtures."""
        self.analyzer = JoinAbuseAnalyzer()
        self.logger = getLogger("test")
    
    def test_analyze_no_join_requests(self) -> None:
        """Test analysis when no join requests were captured."""
        capture = PacketCapture(self.logger)
        
        result = self.analyzer.analyze(capture)
        
        self.assertFalse(result["success"])
        self.assertIn("No join requests captured", result["message"])
    
    def test_analyze_join_flood(self) -> None:
        """Test analysis of join flood attack."""
        capture = PacketCapture(self.logger)
        
        # Simulate multiple join requests with different DevNonces
        for i in range(10):
            capture.capture_uplink(
                phy_payload=f"join_{i}".encode(),
                packet_type="join_request",
                metadata={"phase": "execute", "flood": True, "dev_nonce": f"nonce_{i}"},
            )
        capture.capture_uplink(
            phy_payload=b"join_3",
            packet_type="join_request",
            metadata={"phase": "execute", "flood": True, "dev_nonce": "nonce_3"},
        )
        
        result = self.analyzer.analyze(capture)
        
        self.assertTrue(result["success"])
        self.assertIn("Join flood executed", result["message"])
        self.assertEqual(result["metrics"]["join_requests_sent"], 11)
        self.assertEqual(result["metrics"]["unique_dev_nonces"], 10)
        self.assertEqual(result["metrics"]["replayed_dev_nonces"], 1)
        self.assertEqual(result["metrics"]["attack_type"], "join_flood")
    
    def test_analyze_join_flood_with_accepts(self) -> None:
        """Test analysis of join flood with join accepts received."""
        capture = PacketCapture(self.logger)
        
        # Simulate 10 join requests
        for i in range(10):
            capture.capture_uplink(
                phy_payload=f"join_{i}".encode(),
                packet_type="join_request",
                metadata={"phase": "execute", "flood": True, "dev_nonce": f"nonce_{i}"},
            )
        
        # Simulate 2 join accepts (20% acceptance rate - indicates rate limiting)
        capture.capture_downlink(
            phy_payload=b"\x20\x01\x02\x03",
            packet_type="join_accept",
            metadata={"response_to": "join_request"},
        )
        capture.capture_downlink(
            phy_payload=b"\x20\x04\x05\x06",
            packet_type="join_accept",
            metadata={"response_to": "join_request"},
        )
        
        result = self.analyzer.analyze(capture)
        
        self.assertTrue(result["success"])
        self.assertIn("possible rate limiting detected", result["message"])
        self.assertEqual(result["metrics"]["join_requests_sent"], 10)
        self.assertEqual(result["metrics"]["join_accepts_received"], 2)
        self.assertEqual(result["metrics"]["join_accept_ratio"], 0.2)


class TestVirtualDevice(unittest.TestCase):
    """Test VirtualDevice functionality."""
    
    def test_virtual_device_creation(self) -> None:
        """Test VirtualDevice can be created."""
        dev_eui = bytes.fromhex("0011223344556677")
        join_eui = bytes.fromhex("0011223344556677")
        app_key = bytes.fromhex("00112233445566770011223344556677")
        
        device = VirtualDevice(dev_eui, join_eui, app_key)
        
        self.assertEqual(device.dev_eui, dev_eui)
        self.assertEqual(device.join_eui, join_eui)
        self.assertEqual(device.app_key, app_key)
        self.assertEqual(device.dev_eui_hex, "0011223344556677")
    
    def test_virtual_device_build_join_request(self) -> None:
        """Test VirtualDevice can build JoinRequest."""
        dev_eui = bytes.fromhex("0011223344556677")
        join_eui = bytes.fromhex("0011223344556677")
        app_key = bytes.fromhex("00112233445566770011223344556677")
        
        device = VirtualDevice(dev_eui, join_eui, app_key)
        
        # Build join request
        join_request = device.build_join_request()
        
        # Check DevNonce was generated
        self.assertNotEqual(device.dev_nonce, b"")
        self.assertEqual(len(device.dev_nonce), 2)
        
        # Check join request is non-empty
        self.assertGreater(len(join_request), 0)
    
    def test_virtual_device_unique_dev_nonces(self) -> None:
        """Test VirtualDevice generates unique DevNonces."""
        dev_eui = bytes.fromhex("0011223344556677")
        join_eui = bytes.fromhex("0011223344556677")
        app_key = bytes.fromhex("00112233445566770011223344556677")
        
        device = VirtualDevice(dev_eui, join_eui, app_key)
        
        # Build multiple join requests
        dev_nonces = []
        for _ in range(10):
            device.build_join_request()
            dev_nonces.append(device.dev_nonce)
        
        # Check all DevNonces are unique
        self.assertEqual(len(dev_nonces), len(set(dev_nonces)))


class TestJoinAbuseAttack(unittest.TestCase):
    """Test JoinAbuseAttack functionality."""
    
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
        self.capture = PacketCapture(self.logger)
        self.attack_config = JoinFloodConfigV1(
            mode="flood",
            flood_count=10,
            flood_interval_sec=0.1,
            virtual_devices=3,
        )
        self.ctx = AttackContext(
            services=AttackServices(
                device=self.device,
                gateway=self.gateway,
                logger=self.logger,
                capture=self.capture,
                metrics=None,
            ),
            input=AttackInput(
                typed_config=self.attack_config,
                expected_behavior=None,
                radio=self.radio,
                timeout_sec=30.0,
            ),
        )

    def test_join_abuse_attack_creation(self) -> None:
        """Test JoinAbuseAttack can be created as a plugin."""
        attack = JoinAbuseAttack()

        self.assertEqual(attack.name, "join_flood")

    def test_join_abuse_attack_uses_context_config(self) -> None:
        """Test JoinAbuseAttack uses typed context config."""
        self.assertEqual(self.ctx.config.mode, "flood")
        self.assertEqual(self.ctx.config.flood_count, 10)
        self.assertEqual(self.ctx.config.virtual_devices, 3)

    def test_generate_virtual_devices(self) -> None:
        """Test virtual device generation."""
        attack = JoinAbuseAttack()
        devices = attack._generate_virtual_devices(self.ctx, 5)
        
        self.assertEqual(len(devices), 5)
        
        # Check all devices have unique DevEUIs
        dev_euis = [d.dev_eui for d in devices]
        self.assertEqual(len(dev_euis), len(set(dev_euis)))
        
        # Check all devices have the same JoinEUI and AppKey as main device
        for device in devices:
            self.assertEqual(device.join_eui, self.device._join_eui)
            self.assertEqual(device.app_key, self.device._app_key)
    
    def test_generate_virtual_devices_sequential_euis(self) -> None:
        """Test that generated DevEUIs follow sequential pattern."""
        attack = JoinAbuseAttack()
        devices = attack._generate_virtual_devices(self.ctx, 3)
        
        # Check DevEUIs are sequential
        eui_0 = int.from_bytes(devices[0].dev_eui, byteorder="big")
        eui_1 = int.from_bytes(devices[1].dev_eui, byteorder="big")
        eui_2 = int.from_bytes(devices[2].dev_eui, byteorder="big")
        
        self.assertEqual(eui_1, eui_0 + 1)
        self.assertEqual(eui_2, eui_1 + 1)


if __name__ == "__main__":
    unittest.main()
