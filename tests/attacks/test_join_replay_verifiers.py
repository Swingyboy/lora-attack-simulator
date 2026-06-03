"""Tests for join replay verifiers."""

from __future__ import annotations

import unittest
import unittest.mock
from logging import getLogger
from unittest.mock import MagicMock, Mock

from lorawan_sim.attacks.join_replay_verifiers import (
    DuplicateDevNonceVerifier,
    JoinStepResult,
    MemoryDepthVerifier,
    RollbackDevNonceVerifier,
)


class TestJoinStepResult(unittest.TestCase):
    """Test JoinStepResult dataclass."""
    
    def test_success_property_all_true(self) -> None:
        """Test success property when all conditions met."""
        result = JoinStepResult(
            dev_nonce=b"\x00\x01",
            join_accepted=True,
            session_established=True,
            uplink_sent=True,
            timestamp=123.45,
        )
        
        self.assertTrue(result.success)
    
    def test_success_property_join_not_accepted(self) -> None:
        """Test success property when JoinAccept not received."""
        result = JoinStepResult(
            dev_nonce=b"\x00\x01",
            join_accepted=False,
            session_established=False,
            uplink_sent=False,
            timestamp=123.45,
        )
        
        self.assertFalse(result.success)
    
    def test_success_property_session_not_established(self) -> None:
        """Test success property when session not established."""
        result = JoinStepResult(
            dev_nonce=b"\x00\x01",
            join_accepted=True,
            session_established=False,
            uplink_sent=False,
            timestamp=123.45,
        )
        
        self.assertFalse(result.success)
    
    def test_success_property_uplink_not_sent(self) -> None:
        """Test success property when uplink not sent."""
        result = JoinStepResult(
            dev_nonce=b"\x00\x01",
            join_accepted=True,
            session_established=True,
            uplink_sent=False,
            timestamp=123.45,
        )
        
        self.assertFalse(result.success)


class TestDuplicateDevNonceVerifier(unittest.TestCase):
    """Test DuplicateDevNonceVerifier functionality."""
    
    def setUp(self) -> None:
        """Set up test fixtures."""
        self.verifier = DuplicateDevNonceVerifier()
        self.logger = getLogger("test")
        self.device = MagicMock()
        self.gateway = MagicMock()
        self.radio = MagicMock()
        self.execute_join_step_fn = MagicMock()
    
    def test_verify_secure_behavior(self) -> None:
        """Test verification when NS rejects duplicate DevNonce (SECURE)."""
        dev_nonce = b"\xAB\xCD"
        
        results = [
            # First join: success
            JoinStepResult(
                dev_nonce=dev_nonce,
                join_accepted=True,
                session_established=True,
                uplink_sent=True,
                timestamp=100.0,
            ),
            # Second join with same DevNonce: rejected by NS
            JoinStepResult(
                dev_nonce=dev_nonce,
                join_accepted=False,
                session_established=False,
                uplink_sent=False,
                timestamp=130.0,
            ),
        ]
        
        verification = self.verifier.verify(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            results=results,
            execute_join_step_fn=self.execute_join_step_fn,
            inter_message_delay_sec=30.0,
            logger=self.logger,
        )
        
        self.assertEqual(verification["security_status"], "SECURE")
        self.assertEqual(verification["verification_phase"], "duplicate_devnonce")
        self.assertIn("rejected", verification["message"])
        self.assertTrue(verification["first_join_success"])
        self.assertTrue(verification["second_join_rejected"])
        
        # Should not execute additional joins
        self.execute_join_step_fn.assert_not_called()
    
    def test_verify_vulnerable_behavior(self) -> None:
        """Test verification when NS accepts duplicate DevNonce (VULNERABLE)."""
        dev_nonce = b"\xAB\xCD"
        
        results = [
            # First join: success
            JoinStepResult(
                dev_nonce=dev_nonce,
                join_accepted=True,
                session_established=True,
                uplink_sent=True,
                timestamp=100.0,
            ),
            # Second join with same DevNonce: ACCEPTED by NS (vulnerability!)
            JoinStepResult(
                dev_nonce=dev_nonce,
                join_accepted=True,
                session_established=True,
                uplink_sent=True,
                timestamp=130.0,
            ),
        ]
        
        verification = self.verifier.verify(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            results=results,
            execute_join_step_fn=self.execute_join_step_fn,
            inter_message_delay_sec=30.0,
            logger=self.logger,
        )
        
        self.assertEqual(verification["security_status"], "VULNERABLE")
        self.assertEqual(verification["verification_phase"], "duplicate_devnonce")
        self.assertIn("accepted", verification["message"])
        self.assertTrue(verification["first_join_success"])
        self.assertTrue(verification["second_join_accepted"])
    
    def test_verify_insufficient_results(self) -> None:
        """Test verification with insufficient results."""
        results = [
            JoinStepResult(
                dev_nonce=b"\x00\x01",
                join_accepted=True,
                session_established=True,
                uplink_sent=True,
                timestamp=100.0,
            ),
        ]
        
        verification = self.verifier.verify(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            results=results,
            execute_join_step_fn=self.execute_join_step_fn,
            inter_message_delay_sec=30.0,
            logger=self.logger,
        )
        
        self.assertEqual(verification["security_status"], "UNKNOWN")
        self.assertIn("Insufficient results", verification["message"])
        self.assertEqual(verification["results_count"], 1)
    
    def test_verify_different_devnonces_error(self) -> None:
        """Test verification when DevNonces are different (ERROR)."""
        results = [
            JoinStepResult(
                dev_nonce=b"\x00\x01",
                join_accepted=True,
                session_established=True,
                uplink_sent=True,
                timestamp=100.0,
            ),
            JoinStepResult(
                dev_nonce=b"\x00\x02",  # Different!
                join_accepted=False,
                session_established=False,
                uplink_sent=False,
                timestamp=130.0,
            ),
        ]
        
        verification = self.verifier.verify(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            results=results,
            execute_join_step_fn=self.execute_join_step_fn,
            inter_message_delay_sec=30.0,
            logger=self.logger,
        )
        
        self.assertEqual(verification["security_status"], "ERROR")
        self.assertIn("DevNonces are different", verification["message"])
    
    def test_verify_first_join_failed(self) -> None:
        """Test verification when first join failed."""
        dev_nonce = b"\xAB\xCD"
        
        results = [
            # First join: FAILED
            JoinStepResult(
                dev_nonce=dev_nonce,
                join_accepted=False,
                session_established=False,
                uplink_sent=False,
                timestamp=100.0,
            ),
            # Second join (shouldn't matter)
            JoinStepResult(
                dev_nonce=dev_nonce,
                join_accepted=False,
                session_established=False,
                uplink_sent=False,
                timestamp=130.0,
            ),
        ]
        
        verification = self.verifier.verify(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            results=results,
            execute_join_step_fn=self.execute_join_step_fn,
            inter_message_delay_sec=30.0,
            logger=self.logger,
        )
        
        self.assertEqual(verification["security_status"], "UNKNOWN")
        self.assertIn("First join failed", verification["message"])


class TestRollbackDevNonceVerifier(unittest.TestCase):
    """Test RollbackDevNonceVerifier functionality."""
    
    def setUp(self) -> None:
        """Set up test fixtures."""
        self.verifier = RollbackDevNonceVerifier()
        self.logger = getLogger("test")
        self.device = MagicMock()
        self.gateway = MagicMock()
        self.radio = MagicMock()
        self.execute_join_step_fn = MagicMock()
    
    def test_verify_secure_rollback_rejected(self) -> None:
        """Test verification when NS rejects rollback (SECURE)."""
        results = [
            # First join with DevNonce=100: success
            JoinStepResult(
                dev_nonce=b"\x64\x00",  # 100 little-endian
                join_accepted=True,
                session_established=True,
                uplink_sent=True,
                timestamp=100.0,
            ),
            # Second join with DevNonce=99: rejected by NS
            JoinStepResult(
                dev_nonce=b"\x63\x00",  # 99 little-endian
                join_accepted=False,
                session_established=False,
                uplink_sent=False,
                timestamp=130.0,
            ),
        ]
        
        verification = self.verifier.verify(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            results=results,
            execute_join_step_fn=self.execute_join_step_fn,
            inter_message_delay_sec=30.0,
            logger=self.logger,
        )
        
        self.assertEqual(verification["security_status"], "SECURE")
        self.assertEqual(verification["verification_phase"], "devnonce_rollback")
        self.assertIn("rejected", verification["message"])
        self.assertEqual(verification["baseline_devnonce"], 100)
        self.assertEqual(verification["rollback_devnonce"], 99)
        self.assertTrue(verification["first_join_success"])
        self.assertTrue(verification["second_join_rejected"])
    
    def test_verify_vulnerable_rollback_accepted(self) -> None:
        """Test verification when NS accepts rollback (VULNERABLE)."""
        results = [
            # First join with DevNonce=100: success
            JoinStepResult(
                dev_nonce=b"\x64\x00",
                join_accepted=True,
                session_established=True,
                uplink_sent=True,
                timestamp=100.0,
            ),
            # Second join with DevNonce=99: ACCEPTED (vulnerability!)
            JoinStepResult(
                dev_nonce=b"\x63\x00",
                join_accepted=True,
                session_established=True,
                uplink_sent=True,
                timestamp=130.0,
            ),
        ]
        
        verification = self.verifier.verify(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            results=results,
            execute_join_step_fn=self.execute_join_step_fn,
            inter_message_delay_sec=30.0,
            logger=self.logger,
        )
        
        self.assertEqual(verification["security_status"], "VULNERABLE")
        self.assertIn("accepted", verification["message"])
        self.assertEqual(verification["baseline_devnonce"], 100)
        self.assertEqual(verification["rollback_devnonce"], 99)
    
    def test_verify_not_rollback_error(self) -> None:
        """Test verification when second DevNonce not lower (ERROR)."""
        results = [
            JoinStepResult(
                dev_nonce=b"\x64\x00",  # 100
                join_accepted=True,
                session_established=True,
                uplink_sent=True,
                timestamp=100.0,
            ),
            JoinStepResult(
                dev_nonce=b"\x65\x00",  # 101 (higher, not rollback!)
                join_accepted=False,
                session_established=False,
                uplink_sent=False,
                timestamp=130.0,
            ),
        ]
        
        verification = self.verifier.verify(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            results=results,
            execute_join_step_fn=self.execute_join_step_fn,
            inter_message_delay_sec=30.0,
            logger=self.logger,
        )
        
        self.assertEqual(verification["security_status"], "ERROR")
        self.assertIn("not lower", verification["message"])


class TestMemoryDepthVerifier(unittest.TestCase):
    """Test MemoryDepthVerifier functionality."""
    
    def setUp(self) -> None:
        """Set up test fixtures."""
        self.logger = getLogger("test")
        self.device = MagicMock()
        self.gateway = MagicMock()
        self.radio = MagicMock()
    
    def test_verify_secure_all_replays_rejected(self) -> None:
        """Test verification when NS rejects all replays (SECURE)."""
        verifier = MemoryDepthVerifier(replay_indices=[0, 4, 9])
        
        # Generation phase: 10 successful joins
        results = [
            JoinStepResult(
                dev_nonce=(i + 1).to_bytes(2, 'little'),
                join_accepted=True,
                session_established=True,
                uplink_sent=True,
                timestamp=100.0 + i * 30,
            )
            for i in range(10)
        ]
        
        # Mock execute_join_step_fn to reject all replays
        def mock_replay(dev_nonce: bytes) -> JoinStepResult:
            return JoinStepResult(
                dev_nonce=dev_nonce,
                join_accepted=False,  # NS rejects
                session_established=False,
                uplink_sent=False,
                timestamp=500.0,
            )
        
        execute_join_step_fn = Mock(side_effect=mock_replay)
        
        # Mock time.sleep to avoid delays in tests
        with unittest.mock.patch('time.sleep'):
            verification = verifier.verify(
                device=self.device,
                gateway=self.gateway,
                radio=self.radio,
                results=results,
                execute_join_step_fn=execute_join_step_fn,
                inter_message_delay_sec=30.0,
                logger=self.logger,
            )
        
        self.assertEqual(verification["security_status"], "SECURE")
        self.assertEqual(verification["verification_phase"], "devnonce_memory_depth")
        self.assertEqual(verification["replay_count"], 3)
        self.assertEqual(verification["rejected_replay_count"], 3)
        self.assertEqual(verification["successful_generation_count"], 10)
        
        # Should execute 3 replay joins
        self.assertEqual(execute_join_step_fn.call_count, 3)
    
    def test_verify_vulnerable_some_replays_accepted(self) -> None:
        """Test verification when NS accepts some replays (VULNERABLE)."""
        verifier = MemoryDepthVerifier(replay_indices=[0, 4, 9])
        
        # Generation phase: 10 successful joins
        results = [
            JoinStepResult(
                dev_nonce=(i + 1).to_bytes(2, 'little'),
                join_accepted=True,
                session_established=True,
                uplink_sent=True,
                timestamp=100.0 + i * 30,
            )
            for i in range(10)
        ]
        
        # Mock execute_join_step_fn to accept replay at index 0
        call_count = 0
        
        def mock_replay(dev_nonce: bytes) -> JoinStepResult:
            nonlocal call_count
            accepted = (call_count == 0)  # Accept first replay
            call_count += 1
            
            return JoinStepResult(
                dev_nonce=dev_nonce,
                join_accepted=accepted,
                session_established=accepted,
                uplink_sent=False,
                timestamp=500.0,
            )
        
        execute_join_step_fn = Mock(side_effect=mock_replay)
        
        # Mock time.sleep to avoid delays in tests
        with unittest.mock.patch('time.sleep'):
            verification = verifier.verify(
                device=self.device,
                gateway=self.gateway,
                radio=self.radio,
                results=results,
                execute_join_step_fn=execute_join_step_fn,
                inter_message_delay_sec=30.0,
                logger=self.logger,
            )
        
        self.assertEqual(verification["security_status"], "VULNERABLE")
        self.assertEqual(verification["accepted_replay_count"], 1)
        self.assertEqual(verification["replay_count"], 3)
        self.assertIn("accepted_devnonces", verification)
        self.assertEqual(len(verification["accepted_devnonces"]), 1)
    
    def test_verify_no_successful_joins(self) -> None:
        """Test verification when no joins succeeded."""
        verifier = MemoryDepthVerifier(replay_indices=[0, 1, 2])
        
        # All joins failed
        results = [
            JoinStepResult(
                dev_nonce=(i + 1).to_bytes(2, 'little'),
                join_accepted=False,
                session_established=False,
                uplink_sent=False,
                timestamp=100.0 + i * 30,
            )
            for i in range(5)
        ]
        
        execute_join_step_fn = Mock()
        
        verification = verifier.verify(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            results=results,
            execute_join_step_fn=execute_join_step_fn,
            inter_message_delay_sec=30.0,
            logger=self.logger,
        )
        
        self.assertEqual(verification["security_status"], "UNKNOWN")
        self.assertIn("No successful joins", verification["message"])
        self.assertEqual(verification["successful_count"], 0)
        
        # Should not execute any replays
        execute_join_step_fn.assert_not_called()
    
    def test_verify_skip_out_of_range_indices(self) -> None:
        """Test verification skips replay indices out of range."""
        verifier = MemoryDepthVerifier(replay_indices=[0, 5, 10, 20])  # 10, 20 out of range
        
        # Only 5 successful joins
        results = [
            JoinStepResult(
                dev_nonce=(i + 1).to_bytes(2, 'little'),
                join_accepted=True,
                session_established=True,
                uplink_sent=True,
                timestamp=100.0 + i * 30,
            )
            for i in range(5)
        ]
        
        def mock_replay(dev_nonce: bytes) -> JoinStepResult:
            return JoinStepResult(
                dev_nonce=dev_nonce,
                join_accepted=False,
                session_established=False,
                uplink_sent=False,
                timestamp=500.0,
            )
        
        execute_join_step_fn = Mock(side_effect=mock_replay)
        
        # Mock time.sleep to avoid delays in tests
        with unittest.mock.patch('time.sleep'):
            verification = verifier.verify(
                device=self.device,
                gateway=self.gateway,
                radio=self.radio,
                results=results,
                execute_join_step_fn=execute_join_step_fn,
                inter_message_delay_sec=30.0,
                logger=self.logger,
            )
        
        # Should only replay indices 0, 5 (2 replays)
        # Actually, index 5 is also out of range (only 5 items, indices 0-4)
        # So should only replay index 0 (1 replay)
        self.assertEqual(execute_join_step_fn.call_count, 1)
        self.assertEqual(verification["replay_count"], 1)


if __name__ == "__main__":
    unittest.main()
