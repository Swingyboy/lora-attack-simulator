"""Join replay attack engine - refactored to new API."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from lora_attack_toolkit.attacks.base import BaseAttack
from lora_attack_toolkit.attacks.result import AttackResult
from lora_attack_toolkit.attacks.analyzer import AttackAnalyzer
from lora_attack_toolkit.attacks.packet_capture import PacketCapture
from lora_attack_toolkit.attacks.validation import validate_criteria
from lora_attack_toolkit.attacks.builtin.join_replay_generators import (
    DevNonceGenerator,
    DuplicateDevNonceGenerator,
    RollbackDevNonceGenerator,
    MemoryDepthDevNonceGenerator,
)
from lora_attack_toolkit.attacks.builtin.join_replay_verifiers import (
    JoinReplayVerifier,
    JoinStepResult,
    DuplicateDevNonceVerifier,
    RollbackDevNonceVerifier,
    MemoryDepthVerifier,
)
from lora_attack_toolkit.lorawan.lifecycle.join import (
    perform_otaa_join,
    perform_otaa_join_with_devnonce,
)

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.context import AttackContext
    from lora_attack_toolkit.core.schema_v1 import ExpectedBehavior, JoinReplayConfigV1


class JoinReplayAnalyzer(AttackAnalyzer):
    """Analyzer for join replay attack results."""
    
    def analyze(
        self, capture: PacketCapture, expected: ExpectedBehavior | None = None
    ) -> dict[str, Any]:
        """Analyze join replay attack results."""
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
                criteria=expected.security_criteria,
                metrics=metrics,
                capture_stats=stats,
                secure_behavior=expected.secure_behavior,
            )
            result.update(validation.to_dict())
            result["validation_summary"] = validation.get_summary()
        
        return result


class JoinReplayAttack(BaseAttack):
    """
    Generic join replay attack engine using new simplified API.
    
    Supports multiple attack modes:
    - duplicate_devnonce: Replay same DevNonce (100 → 100)
    - devnonce_rollback: Send lower DevNonce after higher (100 → 99)
    - memory_depth: Test NS memory of historical DevNonces
    """
    
    name = "join_replay"
    
    def run(self, ctx: AttackContext) -> AttackResult:
        """
        Execute join replay attack.
        
        Args:
            ctx: Attack context with all services and typed configuration
        
        Returns:
            AttackResult with execution outcome
        """
        ctx.logger.info(f"Starting {self.name} attack")
        
        try:
            # Get typed configuration
            config: JoinReplayConfigV1 = ctx.config
            
            # Create generator and verifier based on mode
            generator, verifier = self._create_mode_strategy(ctx, config)
            
            # Start gateway
            ctx.logger.info("Starting gateway...")
            ctx.gateway.start()
            time.sleep(0.5)
            
            # Execute attack
            join_results = self._execute_generation_phase(ctx, generator, config)
            verification_results = self._execute_verification_phase(
                ctx, verifier, join_results, config
            )
            
            # Store verification results in capture metadata
            ctx.capture.metadata["attack_mode"] = config.mode
            ctx.capture.metadata["verification"] = verification_results
            
            ctx.logger.info(
                f"Join replay attack complete: {verification_results['security_status']}"
            )
            
            # Stop gateway
            ctx.gateway.stop()
            
            # Analyze results
            ctx.logger.info("Analyzing results...")
            analyzer = JoinReplayAnalyzer()
            analysis = analyzer.analyze(ctx.capture, ctx.expected)
            
            return AttackResult(
                attack_name=self.name,
                attack_type="join_replay",
                success=analysis["success"],
                message=analysis["message"],
                metrics=analysis["metrics"],
                captured_packets=len(ctx.capture.uplinks) + len(ctx.capture.downlinks),
                validation_summary=analysis.get("validation_summary"),
                criteria_met=analysis.get("criteria_met"),
            )
            
        except Exception as e:
            ctx.logger.error(f"Attack failed: {e}", exc_info=True)
            return AttackResult(
                attack_name=self.name,
                attack_type="join_replay",
                success=False,
                message=f"Attack execution failed: {str(e)}",
                metrics={},
                error=str(e),
            )
    
    def _create_mode_strategy(
        self, ctx: AttackContext, config: JoinReplayConfigV1
    ) -> tuple[DevNonceGenerator, JoinReplayVerifier]:
        """Create generator and verifier based on attack mode."""
        mode = config.mode
        if mode == "replay":
            mode = "duplicate_devnonce"

        if mode == "duplicate_devnonce":
            # Need to perform first join to get DevNonce to duplicate
            # For now, use a placeholder - will be fixed in execute phase
            dev_nonce = bytes([0x00, 0x64])  # 100
            generator = DuplicateDevNonceGenerator(dev_nonce)
            verifier = DuplicateDevNonceVerifier()
        elif mode == "devnonce_rollback":
            baseline = config.baseline_devnonce or 100
            rollback = config.rollback_devnonce or 99
            generator = RollbackDevNonceGenerator(baseline, rollback)
            verifier = RollbackDevNonceVerifier()
        elif mode in {"memory_depth", "devnonce_memory_depth"}:
            depth = config.memory_depth or 5
            generator = MemoryDepthDevNonceGenerator(depth)
            verifier = MemoryDepthVerifier()
        else:
            raise ValueError(f"Unsupported mode: {config.mode}")
        
        return generator, verifier
    
    def _execute_generation_phase(
        self,
        ctx: AttackContext,
        generator: DevNonceGenerator,
        config: JoinReplayConfigV1,
    ) -> list[JoinStepResult]:
        """Execute generation phase - send DevNonce sequence."""
        ctx.logger.info("=== Generation Phase ===")
        
        dev_nonce_sequence = generator.generate()
        join_results: list[JoinStepResult] = []
        
        ctx.logger.info(f"DevNonce sequence: {len(dev_nonce_sequence)} steps")
        
        for idx, dev_nonce in enumerate(dev_nonce_sequence, start=1):
            if dev_nonce is None:
                dev_nonce_desc = "auto-generated"
            else:
                dev_nonce_int = int.from_bytes(dev_nonce, 'little')
                dev_nonce_desc = f"{dev_nonce_int} (0x{dev_nonce.hex()})"
            
            ctx.logger.info(f"Join step {idx}/{len(dev_nonce_sequence)}: DevNonce={dev_nonce_desc}")
            
            # Execute join step
            result = self._execute_join_step(ctx, dev_nonce, config)
            join_results.append(result)
            
            # Log result
            if result.success:
                ctx.logger.info(f"✓ Join step {idx} succeeded")
            else:
                ctx.logger.warning(f"✗ Join step {idx} failed")
            
            # Wait before next step (except after last step)
            if idx < len(dev_nonce_sequence):
                ctx.logger.debug(f"Waiting {config.inter_message_delay_sec}s before next join...")
                time.sleep(config.inter_message_delay_sec)
        
        return join_results
    
    def _execute_verification_phase(
        self,
        ctx: AttackContext,
        verifier: JoinReplayVerifier,
        results: list[JoinStepResult],
        config: JoinReplayConfigV1,
    ) -> dict[str, Any]:
        """Execute verification phase - verify attack results."""
        ctx.logger.info("=== Verification Phase ===")
        
        # Create join step execution function for verifier
        def execute_join_step_fn(dev_nonce: bytes | None) -> JoinStepResult:
            return self._execute_join_step(ctx, dev_nonce, config)
        
        verification_results = verifier.verify(
            device=ctx.device,
            gateway=ctx.gateway,
            radio=ctx.radio,
            results=results,
            execute_join_step_fn=execute_join_step_fn,
            inter_message_delay_sec=config.inter_message_delay_sec,
            logger=ctx.logger,
        )
        
        return verification_results
    
    def _execute_join_step(
        self, ctx: AttackContext, dev_nonce: bytes | None, config: JoinReplayConfigV1
    ) -> JoinStepResult:
        """Execute a single join step."""
        timestamp = time.time()
        
        if dev_nonce is None:
            # Auto-generate DevNonce (device generates fresh value)
            ctx.logger.debug("Performing OTAA join with auto-generated DevNonce...")
            
            join_success = perform_otaa_join(
                device=ctx.device,
                gateway=ctx.gateway,
                radio=ctx.radio,
                timeout_sec=config.join_accept_timeout_sec,
                logger=ctx.logger,
            )
            
            # Capture the DevNonce that was generated
            used_dev_nonce = ctx.device.runtime.dev_nonce
        else:
            # Use specific DevNonce
            dev_nonce_int = int.from_bytes(dev_nonce, 'little')
            ctx.logger.debug(f"Performing OTAA join with DevNonce={dev_nonce_int}...")
            
            ns_responded, join_success = perform_otaa_join_with_devnonce(
                device=ctx.device,
                gateway=ctx.gateway,
                radio=ctx.radio,
                dev_nonce=dev_nonce,
                timeout_sec=config.join_accept_timeout_sec,
                logger=ctx.logger,
            )
            
            used_dev_nonce = dev_nonce
        
        return JoinStepResult(
            dev_nonce=used_dev_nonce,
            join_accepted=join_success,
            session_established=join_success,
            uplink_sent=join_success,  # Simplified - assume uplink sent if join successful
            timestamp=timestamp,
        )
