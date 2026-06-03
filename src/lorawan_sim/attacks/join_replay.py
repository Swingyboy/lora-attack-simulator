"""Join replay attack engine - generic and extensible."""

from __future__ import annotations

import time
from logging import Logger
from typing import TYPE_CHECKING, Any, Callable

from lorawan_sim.attacks.analyzer import AttackAnalyzer
from lorawan_sim.attacks.base import AttackConfig, BaseAttack
from lorawan_sim.attacks.packet_capture import CapturedPacket, PacketCapture
from lorawan_sim.attacks.validation import validate_criteria
from lorawan_sim.attacks.join_replay_generators import DevNonceGenerator
from lorawan_sim.attacks.join_replay_verifiers import (
    JoinReplayVerifier,
    JoinStepResult,
)
from lorawan_sim.lorawan.lifecycle.join import (
    perform_otaa_join,
    perform_otaa_join_with_devnonce,
    wait_for_rx_windows,
)
from lorawan_sim.lorawan.device.model import SimulatedDevice
from lorawan_sim.lorawan.gateway.model import GatewaySimulator
from lorawan_sim.lorawan.scenario.schema import RadioMetadata

if TYPE_CHECKING:
    from lorawan_sim.lorawan.scenario.schema_v1 import ExpectedBehavior, AttackTiming


class JoinReplayAnalyzer(AttackAnalyzer):
    """Analyzer for join replay attack results."""
    
    def analyze(
        self, capture: PacketCapture, expected: ExpectedBehavior | None = None
    ) -> dict[str, Any]:
        """
        Analyze join replay attack results.
        
        For join replay attacks:
        - Verify generation phase completed successfully
        - Check verification phase results
        - Determine security status (SECURE, VULNERABLE, UNKNOWN, ERROR)
        """
        stats = capture.get_stats()
        
        # Extract attack metadata from capture
        metadata = capture.metadata
        attack_mode = metadata.get("attack_mode", "unknown")
        verification = metadata.get("verification", {})
        security_status = verification.get("security_status", "UNKNOWN")
        
        # Count join-related packets
        join_requests = [p for p in capture.uplinks if p.packet_type == "join_request"]
        join_accepts = [p for p in capture.downlinks if p.packet_type == "join_accept"]
        
        metrics = {
            "attack_type": "join_replay",
            "attack_mode": attack_mode,
            "join_requests_sent": len(join_requests),
            "join_accepts_received": len(join_accepts),
            "security_status": security_status,
            "total_uplinks": stats["total_uplinks"],
            "total_downlinks": stats["total_downlinks"],
        }
        
        # Add verification results
        metrics.update(verification)
        
        # Determine success (attack found vulnerability = False, NS secure = True)
        success = security_status == "SECURE"
        
        if security_status == "VULNERABLE":
            message = verification.get("message", "NS accepted invalid DevNonce")
        elif security_status == "SECURE":
            message = verification.get("message", "NS correctly rejected invalid DevNonces")
        elif security_status == "ERROR":
            message = verification.get("message", "Attack execution error")
        else:
            message = "Attack results inconclusive"
        
        result = {
            "success": success,
            "message": message,
            "metrics": metrics,
        }
        
        # Add validation if expected behavior provided
        if expected:
            validation = validate_criteria(
                attack_type="join_replay",
                criteria=expected.success_criteria,
                metrics=metrics,
                capture_stats=stats,
                secure_behavior=expected.secure_behavior,
            )
            result["validation"] = validation
        
        return result


class JoinReplayAttack(BaseAttack):
    """
    Generic join replay attack engine.
    
    Supports multiple attack modes:
    - duplicate_devnonce: Replay same DevNonce (100 → 100)
    - devnonce_rollback: Send lower DevNonce after higher (100 → 99)
    - devnonce_memory_depth: Test NS memory of historical DevNonces (1 → 2 → ... → N, then replay)
    """
    
    def __init__(
        self,
        config: AttackConfig,
        device: SimulatedDevice,
        gateway: GatewaySimulator,
        radio: RadioMetadata,
        timing: AttackTiming,
        generator: DevNonceGenerator,
        verifier: JoinReplayVerifier,
        logger: Logger,
        expected_behavior: ExpectedBehavior | None = None,
    ):
        """
        Initialize join replay attack.
        
        Args:
            config: Attack configuration
            device: Simulated device
            gateway: Gateway simulator
            radio: Radio metadata
            timing: Attack timing parameters
            generator: DevNonce sequence generator
            verifier: Attack verifier
            logger: Logger instance
            expected_behavior: Expected behavior for validation
        """
        super().__init__(
            config=config,
            device=device,
            gateway=gateway,
            radio=radio,
            timing=timing,
            logger=logger,
            expected_behavior=expected_behavior,
        )
        
        self.generator = generator
        self.verifier = verifier
        self.inter_message_delay_sec = timing.inter_message_delay_sec
        
        # Attack state
        self._join_results: list[JoinStepResult] = []
    
    @property
    def analyzer(self) -> AttackAnalyzer:
        """Get analyzer for this attack."""
        return JoinReplayAnalyzer()
    
    def setup(self) -> None:
        """
        Setup phase: start gateway and prepare for attack.
        
        No initial join needed - generation phase handles all joins.
        """
        self.logger.info(f"Join replay attack setup: mode={self.config.attack_type}")
        self.gateway.start()
        
        # Wait for gateway to be ready
        time.sleep(0.5)
        
        self.logger.info("Join replay attack setup complete")
    
    def execute(self) -> None:
        """
        Execute attack: generation phase + verification phase.
        
        Generation phase:
        1. Generator yields DevNonce sequence
        2. For each DevNonce: execute join step
        3. Store results
        
        Verification phase:
        1. Verifier analyzes results
        2. May execute additional joins (e.g., memory depth replay)
        3. Determines security status
        """
        self.logger.info("Executing join replay attack")
        
        # === GENERATION PHASE ===
        self.logger.info("=== Generation Phase ===")
        dev_nonce_sequence = self.generator.generate()
        self.logger.info(f"Generated sequence: {len(dev_nonce_sequence)} join steps")
        
        for idx, dev_nonce in enumerate(dev_nonce_sequence, start=1):
            if dev_nonce is None:
                dev_nonce_desc = "auto-generated"
            else:
                dev_nonce_int = int.from_bytes(dev_nonce, 'little')
                dev_nonce_desc = f"{dev_nonce_int} (0x{dev_nonce.hex()})"
            
            self.logger.info(f"Join step {idx}/{len(dev_nonce_sequence)}: DevNonce={dev_nonce_desc}")
            
            # Execute join step
            result = self._execute_join_step(dev_nonce)
            self._join_results.append(result)
            
            # Log result
            if result.success:
                self.logger.info(f"✓ Join step {idx} succeeded")
            else:
                self.logger.warning(f"✗ Join step {idx} failed")
            
            # Wait before next step (except after last step)
            if idx < len(dev_nonce_sequence):
                self.logger.debug(f"Waiting {self.inter_message_delay_sec}s before next join...")
                time.sleep(self.inter_message_delay_sec)
        
        # === VERIFICATION PHASE ===
        self.logger.info("=== Verification Phase ===")
        
        verification_results = self.verifier.verify(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            results=self._join_results,
            execute_join_step_fn=self._execute_join_step,
            inter_message_delay_sec=self.inter_message_delay_sec,
            logger=self.logger,
        )
        
        # Store verification results in capture metadata
        self.capture.metadata["attack_mode"] = self.config.config.get("mode", "unknown")
        self.capture.metadata["verification"] = verification_results
        
        self.logger.info(
            f"Join replay attack complete: {verification_results['security_status']}"
        )
    
    def _execute_join_step(self, dev_nonce: bytes | None) -> JoinStepResult:
        """
        Execute a single join step.
        
        Args:
            dev_nonce: DevNonce to use, or None to auto-generate
            
        Returns:
            JoinStepResult with join outcome
        """
        timestamp = time.time()
        
        if dev_nonce is None:
            # Auto-generate DevNonce (device generates fresh value)
            self.logger.debug("Performing OTAA join with auto-generated DevNonce...")
            
            join_success = perform_otaa_join(
                device=self.device,
                gateway=self.gateway,
                radio=self.radio,
                timeout_sec=self.timing.join_accept_timeout_sec,
                logger=self.logger,
            )
            
            # Capture the DevNonce that was generated
            used_dev_nonce = self.device.runtime.dev_nonce
        else:
            # Use specific DevNonce
            dev_nonce_int = int.from_bytes(dev_nonce, 'little')
            self.logger.debug(f"Performing OTAA join with DevNonce={dev_nonce_int}...")
            
            ns_responded, join_success = perform_otaa_join_with_devnonce(
                device=self.device,
                gateway=self.gateway,
                radio=self.radio,
                dev_nonce=dev_nonce,
                timeout_sec=self.timing.join_accept_timeout_sec,
                logger=self.logger,
            )
            
            used_dev_nonce = dev_nonce
            
            # Note: ns_responded=True means NS sent JoinAccept
            # join_success=True means device could parse it
            # We consider join_accepted = ns_responded (NS sent JoinAccept)
            if not ns_responded:
                join_success = False
        
        # Determine if join was accepted
        join_accepted = join_success
        session_established = join_success
        
        if not join_success:
            # Join failed - return result without sending uplink
            return JoinStepResult(
                dev_nonce=used_dev_nonce,
                join_accepted=False,
                session_established=False,
                uplink_sent=False,
                timestamp=timestamp,
            )
        
        # Join succeeded - send test uplink to confirm session
        self.logger.debug(f"Waiting {self.inter_message_delay_sec}s before test uplink...")
        time.sleep(self.inter_message_delay_sec)
        
        # Send test uplink
        self.logger.debug("Sending test uplink to confirm session...")
        uplink_sent = False
        try:
            test_payload = bytes.fromhex("CAFEBABE")
            uplink = self.device.build_data_uplink(
                payload=test_payload, f_port=10, confirmed=False
            )
            self.gateway.forward_uplink(uplink, self.radio)
            uplink_sent = True
            self.logger.debug("Test uplink sent successfully")
        except Exception as e:
            self.logger.warning(f"Could not send test uplink: {e}")
        
        # Wait for RX windows (collect any downlink responses)
        self.logger.debug("Waiting for RX windows...")
        downlinks = wait_for_rx_windows(
            gateway=self.gateway,
            rx1_delay_sec=self.timing.rx1_delay_sec,
            rx2_delay_sec=self.timing.rx2_delay_sec,
            logger=self.logger,
        )
        
        if downlinks:
            self.logger.debug(f"Received {len(downlinks)} downlink(s) during RX windows")
        
        # Capture join request in packet capture
        self.capture.capture_uplink(
            phy_payload=b"",
            packet_type="join_request",
            metadata={
                "dev_nonce": used_dev_nonce.hex(),
                "join_accepted": join_accepted,
                "uplink_sent": uplink_sent,
                "timestamp": timestamp,
            },
        )
        
        # Capture JoinAccept if received
        if join_accepted:
            self.capture.capture_downlink(
                phy_payload=b"",
                packet_type="join_accept",
                metadata={
                    "dev_nonce": used_dev_nonce.hex(),
                    "timestamp": timestamp,
                },
            )
        
        return JoinStepResult(
            dev_nonce=used_dev_nonce,
            join_accepted=join_accepted,
            session_established=session_established,
            uplink_sent=uplink_sent,
            timestamp=timestamp,
        )
    
    def teardown(self) -> None:
        """Teardown phase: stop gateway."""
        self.logger.info("Join replay attack teardown")
        self.gateway.stop()
