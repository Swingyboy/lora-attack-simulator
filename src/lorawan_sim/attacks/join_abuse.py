"""Join procedure abuse attacks."""

from __future__ import annotations

import secrets
import time
from logging import Logger
from typing import TYPE_CHECKING, Any

from lorawan_sim.attacks.analyzer import AttackAnalyzer
from lorawan_sim.attacks.base import AttackConfig, BaseAttack
from lorawan_sim.attacks.packet_capture import CapturedPacket, PacketCapture
from lorawan_sim.attacks.validation import validate_criteria
from lorawan_sim.lorawan.lifecycle.join import (
    perform_otaa_join,
    perform_otaa_join_with_devnonce,
    wait_for_rx_windows,
)
from lorawan_sim.lorawan.device.model import SimulatedDevice
from lorawan_sim.lorawan.gateway.model import GatewaySimulator
from lorawan_sim.lorawan.scenario.schema import RadioMetadata
from lorawan_sim.lorawan.protocol.frames import build_join_request

if TYPE_CHECKING:
    from lorawan.scenario.schema_v1 import ExpectedBehavior, AttackTiming


class JoinAbuseAnalyzer(AttackAnalyzer):
    """Analyzer for join procedure abuse attack results."""
    
    def analyze(
        self, capture: PacketCapture, expected: ExpectedBehavior | None = None
    ) -> dict[str, Any]:
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
                        criteria=expected.success_criteria,
                        metrics=metrics,
                        capture_stats=stats,
                        secure_behavior=expected.secure_behavior,
                    )
                    result.update(validation.to_dict())
                    result["validation_summary"] = validation.get_summary()
                
                return result
            else:
                # NS correctly rejected replay
                metrics = {
                    "attack_type": "join_replay",
                    "join_requests_sent": len(join_requests),
                    "join_accepts_received": len(join_accepts),
                    "ns_accepted_replay": False,
                    "duplicate_devnonce_accepted": False,
                    "dev_nonce": dev_nonce,
                    "security_status": "SECURE",
                    "total_uplinks": stats["total_uplinks"],
                    "total_downlinks": stats["total_downlinks"],
                }
                
                result = {
                    "success": True,  # Attack executed successfully, NS behaved securely
                    "message": f"✓ NS rejected duplicate DevNonce {dev_nonce} (secure behavior)",
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
                    result.update(validation.to_dict())
                    result["validation_summary"] = validation.get_summary()
                
                return result
        
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
        
        metrics = {
            "attack_type": "join_flood",
            "join_requests_sent": len(join_requests),
            "unique_dev_nonces": len(dev_nonces),
            "replayed_dev_nonces": len(replayed_dev_nonces),
            "join_accepts_received": len(join_accepts),
            "join_accept_ratio": join_accept_ratio,
            "joins_per_second": joins_per_sec,
            "total_uplinks": stats["total_uplinks"],
            "total_downlinks": stats["total_downlinks"],
        }
        
        result = {
            "success": True,
            "message": message,
            "metrics": metrics,
        }
        
        # Add validation if expected behavior provided
        if expected:
            validation = validate_criteria(
                attack_type="join_flood",
                criteria=expected.success_criteria,
                metrics=metrics,
                capture_stats=stats,
                secure_behavior=expected.secure_behavior,
            )
            result.update(validation.to_dict())
            result["validation_summary"] = validation.get_summary()
        
        return result


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
        replay_delay_sec: float = 0.5,
        virtual_devices: int = 1,
        expected: ExpectedBehavior | None = None,
        timing: AttackTiming | None = None,
        inter_message_delay_sec: float = 30.0,
    ) -> None:
        super().__init__(config, device, gateway, logger, expected)
        self.radio = radio
        self.mode = mode
        self.flood_count = flood_count
        self.flood_interval_sec = flood_interval_sec
        self.replay_delay_sec = replay_delay_sec
        self.virtual_devices = virtual_devices
        self.inter_message_delay_sec = inter_message_delay_sec  # Delay between uplink messages
        self._captured_join_request: CapturedPacket | None = None
        self._virtual_device_list: list[VirtualDevice] = []
        
        # Import AttackTiming for defaults
        from lorawan.scenario.schema_v1 import AttackTiming as TimingDefaults
        
        # Use provided timing or defaults
        self.timing = timing if timing else TimingDefaults()
        
        if logger:
            logger.debug(
                f"Attack timing: join_timeout={self.timing.join_accept_timeout_sec}s, "
                f"rx1={self.timing.rx1_delay_sec}s, rx2={self.timing.rx2_delay_sec}s, "
                f"inter_message_delay={self.inter_message_delay_sec}s"
            )
    
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
            
            # Wait inter_message_delay before sending test uplink
            self.logger.info(
                f"Waiting {self.inter_message_delay_sec}s before sending test uplink..."
            )
            time.sleep(self.inter_message_delay_sec)
            
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
            
            # Wait for RX1 and RX2 windows according to LoRaWAN spec
            # This collects any downlink responses to the test uplink
            self.logger.debug(
                "Waiting for RX windows to collect test uplink responses..."
            )
            downlinks = wait_for_rx_windows(
                gateway=self.gateway,
                rx1_delay_sec=self.timing.rx1_delay_sec,
                rx2_delay_sec=self.timing.rx2_delay_sec,
                logger=self.logger,
            )
            
            if downlinks:
                self.logger.info(
                    f"Received {len(downlinks)} downlink(s) during RX windows"
                )
            
            # Wait inter_message_delay before sending replay
            self.logger.info(
                f"Waiting {self.inter_message_delay_sec}s before sending replay attack..."
            )
            time.sleep(self.inter_message_delay_sec)
            
            # Store the captured DevNonce for replay
            self._captured_join_request = CapturedPacket(
                timestamp=time.time(),
                phy_payload=b"",  # We'll rebuild it
                packet_type="join_request",
                metadata={"dev_nonce": captured_dev_nonce.hex(), "phase": "setup"},
            )
            
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
        ns_responded, join_succeeded = perform_otaa_join_with_devnonce(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            dev_nonce=dev_nonce,
            timeout_sec=self.inter_message_delay_sec,  # Use inter-message delay for last pair
            logger=self.logger,
        )
        
        # Key distinction:
        # - ns_responded=True means NS sent JoinAccept (it ACCEPTED the replay)
        # - join_succeeded=True means device could parse the JoinAccept
        # - ns_responded=False means NS did NOT send JoinAccept (secure)
        #
        # Note: If NS sends other message types (UnconfirmedDataDown, etc.),
        # that's NOT counted as accepting the replay - only JoinAccept matters.
        
        if ns_responded:
            if join_succeeded:
                self.logger.warning(
                    "⚠️  VULNERABILITY: NS accepted duplicate DevNonce! Valid JoinAccept received",
                    extra={"security": "FAIL", "dev_nonce": dev_nonce_hex},
                )
            else:
                self.logger.warning(
                    "⚠️  VULNERABILITY: NS accepted duplicate DevNonce! (sent malformed JoinAccept)",
                    extra={"security": "FAIL", "dev_nonce": dev_nonce_hex},
                )
                self.logger.info(
                    "Note: Check DEBUG logs for JoinAccept parsing errors "
                    "(MIC failure, size issues, decryption problems, etc.)"
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
                "ns_accepted": ns_responded,  # True = vulnerability
                "join_succeeded": join_succeeded,
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
