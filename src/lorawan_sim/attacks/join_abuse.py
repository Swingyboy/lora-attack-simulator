"""Join procedure abuse attacks."""

from __future__ import annotations

import secrets
import time
from logging import Logger
from typing import Any

from lorawan_sim.attacks.analyzer import AttackAnalyzer
from lorawan_sim.attacks.base import AttackConfig, BaseAttack
from lorawan_sim.attacks.packet_capture import CapturedPacket, PacketCapture
from lorawan_sim.core.lifecycle.join_helper import (
    perform_otaa_join,
    perform_otaa_join_with_devnonce,
)
from lorawan_sim.domain.device.model import SimulatedDevice
from lorawan_sim.domain.gateway.model import GatewaySimulator
from lorawan_sim.domain.scenario.schema import RadioMetadata
from lorawan_sim.protocol.lorawan.frames import build_join_request


class JoinAbuseAnalyzer(AttackAnalyzer):
    """Analyzer for join procedure abuse attack results."""
    
    def analyze(self, capture: PacketCapture) -> dict[str, Any]:
        """
        Analyze join abuse attack results.
        
        For join-replay mode:
        - Check if first join succeeded (JoinAccept received)
        - Check if second join with same DevNonce was accepted or rejected
        - Secure behavior: NS rejects duplicate DevNonce
        - Vulnerable behavior: NS accepts duplicate DevNonce
        
        For join-flood mode:
        - Count total join requests sent
        - Check if rate limiting detected
        - Measure join request rate
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
                return {
                    "success": False,  # Attack exposed vulnerability
                    "message": f"⚠️  VULNERABILITY: NS accepted duplicate DevNonce {dev_nonce}",
                    "metrics": {
                        "attack_type": "join_replay",
                        "join_requests_sent": len(join_requests),
                        "ns_accepted_replay": True,
                        "security_status": "VULNERABLE",
                        "total_uplinks": stats["total_uplinks"],
                        "total_downlinks": stats["total_downlinks"],
                    },
                }
            else:
                # NS correctly rejected replay
                return {
                    "success": True,  # Attack executed successfully, NS behaved securely
                    "message": f"✓ NS rejected duplicate DevNonce {dev_nonce} (secure behavior)",
                    "metrics": {
                        "attack_type": "join_replay",
                        "join_requests_sent": len(join_requests),
                        "ns_accepted_replay": False,
                        "security_status": "SECURE",
                        "total_uplinks": stats["total_uplinks"],
                        "total_downlinks": stats["total_downlinks"],
                    },
                }
        
        # Join flood analysis (no replay metadata found)
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
        
        message = f"Join flood executed: {len(join_requests)} join requests at {joins_per_sec:.2f} req/s"
        if len(join_accepts) == 0:
            message += " - no accepts received (possible rate limiting)"
        elif join_accept_ratio < 0.5:
            message += " - possible rate limiting detected"
        
        return {
            "success": True,
            "message": message,
            "metrics": {
                "attack_type": "join_flood",
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
        2. Device performs OTAA join (wait for JoinAccept)
        3. Send test uplink to confirm session works
        4. Capture DevNonce for replay
        
        For flood mode:
        1. Start gateway
        2. Generate virtual devices
        """
        self.logger.info(f"Join abuse attack setup: mode={self.mode}")
        self.gateway.start()
        
        # Wait for gateway to be ready
        time.sleep(0.5)
        
        if self.mode == "replay":
            # Perform legitimate OTAA join and wait for JoinAccept
            self.logger.info("Join abuse setup: performing OTAA join...")
            
            join_success = perform_otaa_join(
                device=self.device,
                gateway=self.gateway,
                radio=self.radio,
                timeout_sec=5.0,
                logger=self.logger,
            )
            
            if not join_success:
                self.logger.warning(
                    "OTAA join failed - device credentials may be incorrect or NS unavailable"
                )
                # Store failure state
                self._captured_join_request = None
                return
            
            # Capture the DevNonce that was used
            captured_dev_nonce = self.device.runtime.dev_nonce
            
            self.logger.info(
                f"OTAA join succeeded with DevNonce={captured_dev_nonce.hex()}",
                extra={"dev_nonce": captured_dev_nonce.hex()},
            )
            
            # Send a test uplink to prove session is active
            self.logger.info("Sending test uplink to confirm session...")
            try:
                test_payload = bytes.fromhex("CAFEBABE")
                uplink = self.device.build_data_uplink(
                    payload=test_payload, f_port=10, confirmed=False
                )
                self.gateway.forward_uplink(uplink, self.radio)
                self.logger.info("Test uplink sent successfully")
            except Exception as e:
                self.logger.warning(f"Could not send test uplink: {e}")
            
            # Store the captured DevNonce for replay
            self._captured_join_request = CapturedPacket(
                timestamp=time.time(),
                phy_payload=b"",  # We'll rebuild it
                packet_type="join_request",
                metadata={"dev_nonce": captured_dev_nonce.hex(), "phase": "setup"},
            )
            
            # Short wait for any potential downlink
            time.sleep(0.5)
            
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
        """Execute join replay attack - replay JoinRequest with same DevNonce."""
        if not self._captured_join_request:
            raise RuntimeError("No DevNonce captured - OTAA join may have failed")
        
        self.logger.info("Executing join replay attack")
        
        # Extract captured DevNonce
        dev_nonce_hex = self._captured_join_request.metadata.get("dev_nonce")
        dev_nonce = bytes.fromhex(dev_nonce_hex)
        
        self.logger.info(
            f"Replaying JoinRequest with SAME DevNonce={dev_nonce_hex}",
            extra={"dev_nonce": dev_nonce_hex, "replay": True},
        )
        
        # Attempt join with same DevNonce - NS should reject this!
        join_accepted = perform_otaa_join_with_devnonce(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            dev_nonce=dev_nonce,
            timeout_sec=5.0,
            logger=self.logger,
        )
        
        if join_accepted:
            self.logger.warning(
                "⚠️  VULNERABILITY: NS accepted duplicate DevNonce!",
                extra={"security": "FAIL", "dev_nonce": dev_nonce_hex},
            )
        else:
            self.logger.info(
                "✓ NS rejected duplicate DevNonce (secure behavior)",
                extra={"security": "PASS", "dev_nonce": dev_nonce_hex},
            )
        
        # Capture the result for analysis
        self.capture.capture_uplink(
            phy_payload=b"",
            packet_type="join_request",
            metadata={
                "phase": "execute",
                "replay": True,
                "dev_nonce": dev_nonce_hex,
                "ns_accepted": join_accepted,
            },
        )
        
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
