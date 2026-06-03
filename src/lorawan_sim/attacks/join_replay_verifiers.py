"""Verification logic for join replay attacks."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from lorawan_sim.lorawan.device.model import SimulatedDevice
    from lorawan_sim.lorawan.gateway.model import GatewaySimulator
    from lorawan_sim.lorawan.scenario.schema import RadioMetadata


@dataclass
class JoinStepResult:
    """Result of a single join step."""
    dev_nonce: bytes
    join_accepted: bool  # Did NS send JoinAccept?
    session_established: bool  # Could device derive keys?
    uplink_sent: bool  # Was test uplink transmitted?
    timestamp: float
    
    @property
    def success(self) -> bool:
        """
        Join step is successful if JoinAccept received and uplink sent.
        
        Note: LoRaWAN doesn't guarantee delivery, so we don't verify NS processing.
        """
        return self.join_accepted and self.session_established and self.uplink_sent


class JoinReplayVerifier(ABC):
    """Base class for join replay attack verifiers."""
    
    @abstractmethod
    def verify(
        self,
        device: SimulatedDevice,
        gateway: GatewaySimulator,
        radio: RadioMetadata,
        results: list[JoinStepResult],
        execute_join_step_fn: Callable[[bytes], JoinStepResult],
        inter_message_delay_sec: float,
        logger: Logger,
    ) -> dict[str, Any]:
        """
        Verify NS behavior after join sequence.
        
        Args:
            device: Simulated device
            gateway: Gateway simulator
            radio: Radio metadata
            results: Results from generation phase
            execute_join_step_fn: Function to execute additional join steps
            inter_message_delay_sec: Delay between join steps
            logger: Logger instance
            
        Returns:
            Verification results dict with security_status
        """
        pass


class DuplicateDevNonceVerifier(JoinReplayVerifier):
    """
    Verifier for duplicate DevNonce attack.
    
    Pure analysis - no additional joins executed.
    Checks if second join with same DevNonce was rejected by NS.
    """
    
    def verify(
        self,
        device: SimulatedDevice,
        gateway: GatewaySimulator,
        radio: RadioMetadata,
        results: list[JoinStepResult],
        execute_join_step_fn: Callable[[bytes], JoinStepResult],
        inter_message_delay_sec: float,
        logger: Logger,
    ) -> dict[str, Any]:
        """
        Verify duplicate DevNonce was rejected.
        
        Expected results:
        - results[0]: First join with DevNonce X (should succeed)
        - results[1]: Second join with same DevNonce X (should be rejected)
        """
        if len(results) < 2:
            return {
                "verification_phase": "duplicate_devnonce",
                "security_status": "UNKNOWN",
                "message": "Insufficient results - expected 2 join attempts",
                "results_count": len(results),
            }
        
        first_join = results[0]
        second_join = results[1]
        
        # Verify DevNonces are actually the same
        if first_join.dev_nonce != second_join.dev_nonce:
            return {
                "verification_phase": "duplicate_devnonce",
                "security_status": "ERROR",
                "message": "DevNonces are different - not a duplicate attack",
                "first_devnonce": first_join.dev_nonce.hex(),
                "second_devnonce": second_join.dev_nonce.hex(),
            }
        
        dev_nonce_hex = first_join.dev_nonce.hex()
        
        # Check results
        if not first_join.success:
            return {
                "verification_phase": "duplicate_devnonce",
                "security_status": "UNKNOWN",
                "message": f"First join failed (DevNonce={dev_nonce_hex})",
                "dev_nonce": dev_nonce_hex,
            }
        
        if second_join.join_accepted:
            # VULNERABILITY: NS accepted duplicate DevNonce
            logger.warning(
                f"⚠️  VULNERABILITY: NS accepted duplicate DevNonce {dev_nonce_hex}",
                extra={"security": "FAIL", "dev_nonce": dev_nonce_hex},
            )
            
            return {
                "verification_phase": "duplicate_devnonce",
                "security_status": "VULNERABLE",
                "message": f"NS accepted duplicate DevNonce {dev_nonce_hex}",
                "dev_nonce": dev_nonce_hex,
                "first_join_success": True,
                "second_join_accepted": True,
            }
        else:
            # SECURE: NS rejected duplicate DevNonce
            logger.info(
                f"✓ NS rejected duplicate DevNonce {dev_nonce_hex} (secure behavior)",
                extra={"security": "PASS", "dev_nonce": dev_nonce_hex},
            )
            
            return {
                "verification_phase": "duplicate_devnonce",
                "security_status": "SECURE",
                "message": f"NS rejected duplicate DevNonce {dev_nonce_hex}",
                "dev_nonce": dev_nonce_hex,
                "first_join_success": True,
                "second_join_rejected": True,
            }


class RollbackDevNonceVerifier(JoinReplayVerifier):
    """
    Verifier for DevNonce rollback attack.
    
    Pure analysis - no additional joins executed.
    Checks if NS rejected lower DevNonce after higher one (rollback protection).
    """
    
    def verify(
        self,
        device: SimulatedDevice,
        gateway: GatewaySimulator,
        radio: RadioMetadata,
        results: list[JoinStepResult],
        execute_join_step_fn: Callable[[bytes], JoinStepResult],
        inter_message_delay_sec: float,
        logger: Logger,
    ) -> dict[str, Any]:
        """
        Verify rollback DevNonce was rejected.
        
        Expected results:
        - results[0]: First join with DevNonce X (higher, should succeed)
        - results[1]: Second join with DevNonce Y < X (should be rejected)
        """
        if len(results) < 2:
            return {
                "verification_phase": "devnonce_rollback",
                "security_status": "UNKNOWN",
                "message": "Insufficient results - expected 2 join attempts",
                "results_count": len(results),
            }
        
        first_join = results[0]
        second_join = results[1]
        
        # Convert to integers for comparison
        first_nonce_int = int.from_bytes(first_join.dev_nonce, 'little')
        second_nonce_int = int.from_bytes(second_join.dev_nonce, 'little')
        
        # Verify second is lower (rollback)
        if second_nonce_int >= first_nonce_int:
            return {
                "verification_phase": "devnonce_rollback",
                "security_status": "ERROR",
                "message": "Second DevNonce is not lower - not a rollback attack",
                "first_devnonce": first_nonce_int,
                "second_devnonce": second_nonce_int,
            }
        
        # Check results
        if not first_join.success:
            return {
                "verification_phase": "devnonce_rollback",
                "security_status": "UNKNOWN",
                "message": f"First join failed (DevNonce={first_nonce_int})",
                "baseline_devnonce": first_nonce_int,
            }
        
        if second_join.join_accepted:
            # VULNERABILITY: NS accepted rollback
            logger.warning(
                f"⚠️  VULNERABILITY: NS accepted DevNonce rollback "
                f"({first_nonce_int} → {second_nonce_int})",
                extra={
                    "security": "FAIL",
                    "baseline": first_nonce_int,
                    "rollback": second_nonce_int,
                },
            )
            
            return {
                "verification_phase": "devnonce_rollback",
                "security_status": "VULNERABLE",
                "message": f"NS accepted DevNonce rollback ({first_nonce_int} → {second_nonce_int})",
                "baseline_devnonce": first_nonce_int,
                "rollback_devnonce": second_nonce_int,
                "first_join_success": True,
                "second_join_accepted": True,
            }
        else:
            # SECURE: NS rejected rollback
            logger.info(
                f"✓ NS rejected DevNonce rollback ({first_nonce_int} → {second_nonce_int}) "
                f"(secure behavior)",
                extra={
                    "security": "PASS",
                    "baseline": first_nonce_int,
                    "rollback": second_nonce_int,
                },
            )
            
            return {
                "verification_phase": "devnonce_rollback",
                "security_status": "SECURE",
                "message": f"NS rejected DevNonce rollback ({first_nonce_int} → {second_nonce_int})",
                "baseline_devnonce": first_nonce_int,
                "rollback_devnonce": second_nonce_int,
                "first_join_success": True,
                "second_join_rejected": True,
            }


class MemoryDepthVerifier(JoinReplayVerifier):
    """
    Verifier for DevNonce memory depth testing.
    
    EXECUTES ADDITIONAL JOINS - replays historical DevNonces from generation phase.
    Tests if NS remembers previously used DevNonce values.
    """
    
    def __init__(self, replay_indices: list[int]):
        """
        Initialize verifier.
        
        Args:
            replay_indices: Indices of DevNonces to replay from generation phase
                           e.g., [0, 9, 99, 499] to replay 1st, 10th, 100th, 500th
        """
        self.replay_indices = replay_indices
    
    def verify(
        self,
        device: SimulatedDevice,
        gateway: GatewaySimulator,
        radio: RadioMetadata,
        results: list[JoinStepResult],
        execute_join_step_fn: Callable[[bytes], JoinStepResult],
        inter_message_delay_sec: float,
        logger: Logger,
    ) -> dict[str, Any]:
        """
        Replay historical DevNonces and check if NS accepts them.
        
        Steps:
        1. Extract successful DevNonces from generation phase
        2. For each replay index, get the corresponding DevNonce
        3. Execute join with that old DevNonce
        4. Check if NS sends JoinAccept
        5. Return VULNERABLE if any replayed DevNonce is accepted
        """
        # Filter successful joins
        successful_joins = [r for r in results if r.success]
        
        if not successful_joins:
            return {
                "verification_phase": "devnonce_memory_depth",
                "security_status": "UNKNOWN",
                "message": "No successful joins to verify",
                "generation_count": len(results),
                "successful_count": 0,
            }
        
        logger.info(
            f"Starting memory depth verification: replaying {len(self.replay_indices)} "
            f"DevNonces from {len(successful_joins)} successful joins"
        )
        
        replay_results = []
        
        for idx in self.replay_indices:
            if idx >= len(successful_joins):
                logger.warning(
                    f"Replay index {idx} out of range (only {len(successful_joins)} "
                    f"successful joins), skipping"
                )
                continue
            
            old_dev_nonce = successful_joins[idx].dev_nonce
            old_nonce_int = int.from_bytes(old_dev_nonce, 'little')
            
            logger.info(
                f"Replaying DevNonce from join #{idx + 1}: {old_nonce_int} "
                f"(0x{old_dev_nonce.hex()})"
            )
            
            # Wait before replay
            time.sleep(inter_message_delay_sec)
            
            # Execute join with old DevNonce
            replay_result = execute_join_step_fn(old_dev_nonce)
            
            replay_results.append({
                "original_index": idx,
                "dev_nonce": old_dev_nonce.hex(),
                "dev_nonce_int": old_nonce_int,
                "ns_accepted": replay_result.join_accepted,
                "session_established": replay_result.session_established,
            })
            
            if replay_result.join_accepted:
                logger.warning(
                    f"⚠️  VULNERABILITY: NS accepted replayed DevNonce {old_nonce_int} "
                    f"from join #{idx + 1}",
                    extra={"security": "FAIL", "dev_nonce": old_nonce_int, "index": idx},
                )
            else:
                logger.info(
                    f"✓ NS rejected replayed DevNonce {old_nonce_int} (secure)",
                    extra={"security": "PASS", "dev_nonce": old_nonce_int, "index": idx},
                )
        
        # Analyze results
        accepted_count = sum(1 for r in replay_results if r["ns_accepted"])
        
        if accepted_count > 0:
            # VULNERABLE: At least one replay was accepted
            accepted_nonces = [
                r["dev_nonce_int"] for r in replay_results if r["ns_accepted"]
            ]
            
            return {
                "verification_phase": "devnonce_memory_depth",
                "security_status": "VULNERABLE",
                "message": f"NS accepted {accepted_count}/{len(replay_results)} replayed DevNonces",
                "generation_count": len(results),
                "successful_generation_count": len(successful_joins),
                "replay_count": len(replay_results),
                "accepted_replay_count": accepted_count,
                "accepted_devnonces": accepted_nonces,
                "replay_results": replay_results,
            }
        else:
            # SECURE: All replays were rejected
            return {
                "verification_phase": "devnonce_memory_depth",
                "security_status": "SECURE",
                "message": f"NS rejected all {len(replay_results)} replayed DevNonces",
                "generation_count": len(results),
                "successful_generation_count": len(successful_joins),
                "replay_count": len(replay_results),
                "rejected_replay_count": len(replay_results),
                "replay_results": replay_results,
            }
