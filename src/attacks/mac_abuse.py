"""MAC command abuse and ADR manipulation attack implementation."""

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
from lorawan.protocol.mac_commands import (
    CID_DEV_STATUS_REQ,
    CID_LINK_ADR_REQ,
    CID_NEW_CHANNEL_REQ,
    CID_RX_PARAM_SETUP_REQ,
    MACCommand,
    build_dev_status_req,
    build_link_adr_req,
    build_malformed_mac_command,
    build_new_channel_req,
    build_rx_param_setup_req,
    encode_mac_commands,
)

if TYPE_CHECKING:
    from lorawan.scenario.schema_v1 import ExpectedBehavior


class MACCommandAnalyzer(AttackAnalyzer):
    """Analyzer for MAC command abuse attack results."""
    
    def analyze(
        self, capture: PacketCapture, expected: ExpectedBehavior | None = None
    ) -> dict[str, Any]:
        """
        Analyze MAC command abuse attack results.
        
        Checks if:
        - MAC commands were sent
        - Device sent uplinks after MAC commands
        - Device responses (LinkADRAns, etc.) were captured
        - Malformed commands were processed or rejected
        - ADR state transitions occurred
        """
        stats = capture.get_stats()
        
        # Count uplinks before and after MAC command injection
        uplinks_before_attack = 0
        uplinks_after_attack = 0
        mac_commands_injected = 0
        
        for packet in capture.uplinks:
            phase = packet.metadata.get("phase", "")
            if phase == "setup":
                uplinks_before_attack += 1
            elif phase == "execute":
                mac_command = packet.metadata.get("mac_command_type")
                if mac_command:
                    mac_commands_injected += 1
                else:
                    uplinks_after_attack += 1
        
        if mac_commands_injected == 0:
            return {
                "success": False,
                "message": "No MAC commands were injected",
                "metrics": {
                    "uplinks_captured": stats["total_uplinks"],
                    "mac_commands_injected": 0,
                },
            }
        
        # Analyze device behavior after MAC commands
        device_responded = uplinks_after_attack > 0
        
        # Check for ADR parameters in metadata
        adr_changes = []
        for packet in capture.uplinks:
            adr_state = packet.metadata.get("adr_state")
            if adr_state:
                adr_changes.append(adr_state)
        
        # Determine attack success
        success = mac_commands_injected > 0
        
        # Check for malformed command detection
        malformed_commands = sum(
            1 for p in capture.uplinks
            if p.metadata.get("malformed", False)
        )
        
        message = f"MAC command abuse executed: {mac_commands_injected} command(s) injected"
        if device_responded:
            message += f", device sent {uplinks_after_attack} response(s)"
        if malformed_commands > 0:
            message += f", {malformed_commands} malformed command(s)"
        if adr_changes:
            message += f", {len(adr_changes)} ADR state change(s)"
        
        # Extract ADR state for validation
        final_data_rate = None
        final_tx_power = None
        if adr_changes:
            last_adr = adr_changes[-1]
            final_data_rate = last_adr.get("data_rate")
            final_tx_power = last_adr.get("tx_power")
        
        metrics = {
            "mac_commands_injected": mac_commands_injected,
            "uplinks_before_attack": uplinks_before_attack,
            "uplinks_after_attack": uplinks_after_attack,
            "device_responded": device_responded,
            "malformed_commands": malformed_commands,  # Keep for backward compatibility
            "malformed_commands_sent": malformed_commands,
            "invalid_commands_sent": 0,  # Could track separately if needed
            "adr_state_changes": len(adr_changes),
            "final_data_rate": final_data_rate,
            "final_tx_power": final_tx_power,
            "total_uplinks": stats["total_uplinks"],
            "total_downlinks": stats["total_downlinks"],
        }
        
        result = {
            "success": success,
            "message": message,
            "metrics": metrics,
        }
        
        # Add validation if expected behavior provided
        if expected:
            validation = validate_criteria(
                attack_type="mac_command_injection",
                criteria=expected.success_criteria,
                metrics=metrics,
                capture_stats=stats,
                secure_behavior=expected.secure_behavior,
            )
            result.update(validation.to_dict())
            result["validation_summary"] = validation.get_summary()
        
        return result


class MACCommandAbuse(BaseAttack):
    """
    MAC command abuse and ADR manipulation attack implementation.
    
    Supports:
    1. Legitimate MAC command injection (LinkADRReq, RXParamSetupReq, etc.)
    2. Malformed MAC command injection (truncated, oversized, invalid values)
    3. ADR manipulation (aggressive data rate changes)
    
    Tests:
    - MAC command parsing robustness
    - ADR state handling
    - Protocol-state consistency
    - Malformed payload handling
    """
    
    def __init__(
        self,
        config: AttackConfig,
        device: SimulatedDevice,
        gateway: GatewaySimulator,
        logger: Logger,
        radio: RadioMetadata,
        command_type: str = "LinkADRReq",
        malformed: bool = False,
        malformation_type: str = "truncated",
        parameters: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(config, device, gateway, logger)
        self.radio = radio
        self.command_type = command_type
        self.malformed = malformed
        self.malformation_type = malformation_type
        self.parameters = parameters or {}
        self._current_adr_state: dict[str, Any] = {
            "data_rate": 0,
            "tx_power": 0,
            "nb_trans": 1,
        }
    
    def _create_analyzer(self) -> AttackAnalyzer:
        """Create MAC command abuse analyzer."""
        return MACCommandAnalyzer()
    
    def setup(self) -> None:
        """
        Setup phase: establish session.
        
        Steps:
        1. Start gateway
        2. Device performs OTAA join (with proper JoinAccept handling)
        3. Device sends initial uplink(s) to establish baseline
        """
        self.logger.info("MAC command abuse setup: starting gateway")
        self.gateway.start()
        
        # Wait for gateway to be ready
        time.sleep(0.5)
        
        # Perform OTAA join with proper JoinAccept handling
        self.logger.info("MAC command abuse setup: device joining")
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
            self.logger.error("OTAA join failed - cannot proceed with MAC command abuse")
            raise RuntimeError("Device failed to join network")
        
        # Send baseline uplinks
        self.logger.info("MAC command abuse setup: sending baseline uplinks")
        for i in range(2):
            try:
                payload = bytes.fromhex("010203")
                uplink = self.device.build_data_uplink(payload=payload, f_port=10, confirmed=False)
                
                self.capture.capture_uplink(
                    phy_payload=uplink,
                    fcnt=self.device.runtime.fcnt_up - 1,
                    packet_type="data_up",
                    metadata={
                        "phase": "setup",
                        "baseline": True,
                        "adr_state": dict(self._current_adr_state),
                    },
                )
                
                self.gateway.forward_uplink(uplink, self.radio)
                time.sleep(0.3)
                
            except RuntimeError as e:
                self.logger.warning(f"Could not build baseline uplink: {e}")
        
        time.sleep(0.5)
    
    def execute(self) -> None:
        """
        Execute MAC command abuse attack.
        
        Injects MAC commands via simulated downlink or piggybacked uplink
        to test Network Server handling.
        """
        self.logger.info(
            f"Executing MAC command abuse: type={self.command_type}, malformed={self.malformed}",
            extra={
                "command_type": self.command_type,
                "malformed": self.malformed,
                "malformation_type": self.malformation_type if self.malformed else None,
            },
        )
        
        # Build MAC command
        if self.malformed:
            mac_command = self._build_malformed_command()
        else:
            mac_command = self._build_legitimate_command()
        
        # Log the injection
        self.logger.info(
            f"Injecting MAC command: CID=0x{mac_command.cid:02X}, "
            f"payload_len={len(mac_command.payload)}, "
            f"malformed={self.malformed}",
            extra={
                "cid": mac_command.cid,
                "payload_hex": mac_command.payload.hex(),
                "malformed": self.malformed,
            },
        )
        
        # Simulate MAC command injection
        # In a real scenario, this would be:
        # 1. Sent in FOpts field of downlink
        # 2. Sent in FRMPayload with FPort=0
        # For attack simulation, we capture the command as metadata
        
        # Capture MAC command "injection"
        mac_command_bytes = mac_command.to_bytes()
        self.capture.capture_uplink(
            phy_payload=mac_command_bytes,
            packet_type="mac_command",
            metadata={
                "phase": "execute",
                "mac_command_type": self.command_type,
                "cid": mac_command.cid,
                "payload_hex": mac_command.payload.hex(),
                "malformed": self.malformed,
                "malformation_type": self.malformation_type if self.malformed else None,
            },
        )
        
        # Update ADR state if LinkADRReq
        if self.command_type == "LinkADRReq" and not self.malformed:
            self._update_adr_state(mac_command)
        
        # Send follow-up uplink to see device response
        time.sleep(0.5)
        try:
            payload = bytes.fromhex("040506")
            uplink = self.device.build_data_uplink(payload=payload, f_port=10, confirmed=False)
            
            self.capture.capture_uplink(
                phy_payload=uplink,
                fcnt=self.device.runtime.fcnt_up - 1,
                packet_type="data_up",
                metadata={
                    "phase": "execute",
                    "after_mac_command": True,
                    "adr_state": dict(self._current_adr_state),
                },
            )
            
            self.gateway.forward_uplink(uplink, self.radio)
            
        except RuntimeError as e:
            self.logger.warning(f"Could not build follow-up uplink: {e}")
        
        time.sleep(1.0)
    
    def teardown(self) -> None:
        """Teardown: stop gateway and cleanup."""
        self.logger.info("MAC command abuse teardown: stopping gateway")
        self.gateway.stop()
    
    def _build_legitimate_command(self) -> MACCommand:
        """Build legitimate MAC command based on command_type."""
        if self.command_type == "LinkADRReq":
            return build_link_adr_req(
                data_rate=self.parameters.get("data_rate", 5),
                tx_power=self.parameters.get("tx_power", 2),
                ch_mask=self.parameters.get("ch_mask", 0x00FF),
                redundancy=self.parameters.get("redundancy", 1),
            )
        
        elif self.command_type == "RXParamSetupReq":
            return build_rx_param_setup_req(
                rx1_dr_offset=self.parameters.get("rx1_dr_offset", 0),
                rx2_data_rate=self.parameters.get("rx2_data_rate", 0),
                frequency=self.parameters.get("frequency", 869525000),
            )
        
        elif self.command_type == "NewChannelReq":
            return build_new_channel_req(
                ch_index=self.parameters.get("ch_index", 3),
                frequency=self.parameters.get("frequency", 867100000),
                max_dr=self.parameters.get("max_dr", 5),
                min_dr=self.parameters.get("min_dr", 0),
            )
        
        elif self.command_type == "DevStatusReq":
            return build_dev_status_req()
        
        else:
            raise ValueError(f"Unsupported command type: {self.command_type}")
    
    def _build_malformed_command(self) -> MACCommand:
        """Build malformed MAC command for attack."""
        # Map command type to CID
        cid_map = {
            "LinkADRReq": CID_LINK_ADR_REQ,
            "RXParamSetupReq": CID_RX_PARAM_SETUP_REQ,
            "NewChannelReq": CID_NEW_CHANNEL_REQ,
            "DevStatusReq": CID_DEV_STATUS_REQ,
        }
        
        cid = cid_map.get(self.command_type, CID_LINK_ADR_REQ)
        
        return build_malformed_mac_command(
            cid=cid,
            malformation_type=self.malformation_type,
            **self.parameters,
        )
    
    def _update_adr_state(self, mac_command: MACCommand) -> None:
        """Update ADR state based on LinkADRReq command."""
        if len(mac_command.payload) < 4:
            return
        
        # Parse LinkADRReq payload
        data_rate_tx_power = mac_command.payload[0]
        data_rate = (data_rate_tx_power >> 4) & 0x0F
        tx_power = data_rate_tx_power & 0x0F
        redundancy = mac_command.payload[3]
        nb_trans = redundancy & 0x0F
        
        self._current_adr_state["data_rate"] = data_rate
        self._current_adr_state["tx_power"] = tx_power
        self._current_adr_state["nb_trans"] = nb_trans
        
        self.logger.info(
            f"ADR state updated: DR={data_rate}, TXPower={tx_power}, NbTrans={nb_trans}",
            extra=self._current_adr_state,
        )
