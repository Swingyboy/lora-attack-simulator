"""Unit tests for replay attack."""

import unittest
from logging import getLogger
from unittest.mock import MagicMock

from lora_attack_toolkit.attacks.base import AttackConfig
from lora_attack_toolkit.attacks.packet_capture import CapturedPacket, PacketCapture
from lora_attack_toolkit.attacks.builtin.replay import ReplayAnalyzer, ReplayAttack
from lora_attack_toolkit.device.model import SimulatedDevice
from lora_attack_toolkit.gateway.model import GatewaySimulator
from lora_attack_toolkit.core.schema import RadioMetadata


class TestReplayAnalyzer(unittest.TestCase):
    """Test ReplayAnalyzer."""
    
    def setUp(self) -> None:
        self.analyzer = ReplayAnalyzer()
        self.logger = getLogger("test")
    
    def test_analyze_insufficient_uplinks(self) -> None:
        """Test analysis with insufficient uplinks."""
        capture = PacketCapture(logger=self.logger)
        capture.capture_uplink(b"\x40\x00\x00\x00\x00", fcnt=0)
        
        result = self.analyzer.analyze(capture)
        
        self.assertFalse(result["success"])
        self.assertIn("insufficient uplinks", result["message"])
    
    def test_analyze_no_replays_detected(self) -> None:
        """Test analysis when no replays detected."""
        capture = PacketCapture(logger=self.logger)
        capture.capture_uplink(b"\x40\x00\x00\x00\x00", fcnt=0)
        capture.capture_uplink(b"\x40\x00\x00\x00\x01", fcnt=1)
        
        result = self.analyzer.analyze(capture)
        
        self.assertFalse(result["success"])
        self.assertIn("No replay packets detected", result["message"])
    
    def test_analyze_successful_replay(self) -> None:
        """Test analysis with successful replay."""
        capture = PacketCapture(logger=self.logger)
        
        original_payload = b"\x40\x00\x00\x00\x00"
        capture.capture_uplink(original_payload, fcnt=0)
        capture.capture_uplink(original_payload, fcnt=0)
        
        result = self.analyzer.analyze(capture)
        
        self.assertTrue(result["success"])
        self.assertIn("replay(s) sent", result["message"])
        self.assertEqual(result["metrics"]["replays_sent"], 1)


class TestPacketCapture(unittest.TestCase):
    """Test packet capture."""
    
    def setUp(self) -> None:
        self.logger = getLogger("test")
        self.capture = PacketCapture(logger=self.logger)
    
    def test_capture_uplink(self) -> None:
        """Test capturing uplink."""
        packet = self.capture.capture_uplink(b"\x40\x00\x00\x00\x00", fcnt=0)
        
        self.assertEqual(len(self.capture.uplinks), 1)
        self.assertEqual(packet.fcnt, 0)
    
    def test_get_stats(self) -> None:
        """Test capture statistics."""
        self.capture.capture_uplink(b"\x40\x00\x00\x00\x00", fcnt=0)
        self.capture.capture_downlink(b"\x60\x00\x00\x00\x00", fcnt=0)
        
        stats = self.capture.get_stats()
        
        self.assertEqual(stats["total_uplinks"], 1)
        self.assertEqual(stats["total_downlinks"], 1)


if __name__ == "__main__":
    unittest.main()
