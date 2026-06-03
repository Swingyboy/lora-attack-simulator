from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any
from logging import Logger

from lorawan.protocol.frames import (
    build_join_request,
    build_unconfirmed_data_up,
    decode_join_accept,
    derive_session_keys,
)
from lorawan.protocol.mac_commands import (
    CID_LINK_ADR_REQ,
    CID_LINK_ADR_ANS,
    CID_RX_PARAM_SETUP_REQ,
    CID_RX_PARAM_SETUP_ANS,
    CID_DEV_STATUS_REQ,
    CID_DEV_STATUS_ANS,
    CID_NEW_CHANNEL_REQ,
    CID_NEW_CHANNEL_ANS,
    CID_DUTY_CYCLE_REQ,
    CID_DUTY_CYCLE_ANS,
    CID_RX_TIMING_SETUP_REQ,
    CID_RX_TIMING_SETUP_ANS,
    MACCommand,
)


@dataclass
class DeviceRadioState:
    """Device radio parameters and ADR state.
    
    Tracks current radio configuration that can be modified by
    Network Server via MAC commands (LinkADRReq, etc.).
    """
    
    data_rate: int = 0           # Current data rate (0-15, maps to SF12-SF7)
    tx_power: int = 14           # Current TX power in dBm (0-15, region-specific)
    ch_mask: int = 0x00FF        # Enabled channels (16-bit mask)
    nb_trans: int = 1            # Number of transmissions per uplink
    rx1_dr_offset: int = 0       # RX1 data rate offset
    rx2_data_rate: int = 0       # RX2 data rate
    rx1_delay: int = 1           # RX1 delay in seconds
    duty_cycle: int = 0          # Duty cycle limitation (0 = no limit)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert radio state to dict for logging."""
        return {
            "data_rate": self.data_rate,
            "tx_power": self.tx_power,
            "ch_mask": f"0x{self.ch_mask:04x}",
            "nb_trans": self.nb_trans,
            "rx1_dr_offset": self.rx1_dr_offset,
            "rx2_data_rate": self.rx2_data_rate,
            "rx1_delay": self.rx1_delay,
            "duty_cycle": self.duty_cycle,
        }


@dataclass
class DeviceRuntime:
    joined: bool = False
    dev_nonce: bytes = b""
    dev_addr_le: bytes = b""
    nwk_s_key: bytes = b""
    app_s_key: bytes = b""
    fcnt_up: int = 0
    fcnt_down: int = 0           # Track downlink frame counter
    radio: DeviceRadioState = field(default_factory=DeviceRadioState)  # Radio state

    @property
    def dev_addr_hex(self) -> str:
        return self.dev_addr_le[::-1].hex() if self.dev_addr_le else ""


class SimulatedDevice:
    def __init__(
        self, 
        dev_eui: str, 
        join_eui: str, 
        app_key: str,
        logger: Logger | None = None,
    ) -> None:
        self._dev_eui = bytes.fromhex(dev_eui)
        self._join_eui = bytes.fromhex(join_eui)
        self._app_key = bytes.fromhex(app_key)
        self._logger = logger
        self.runtime = DeviceRuntime()

    def build_join_request(self) -> bytes:
        self.runtime.dev_nonce = secrets.token_bytes(2)
        return build_join_request(
            join_eui=self._join_eui,
            dev_eui=self._dev_eui,
            dev_nonce=self.runtime.dev_nonce,
            app_key=self._app_key,
        )

    def apply_join_accept(self, phy_payload: bytes) -> None:
        if not self.runtime.dev_nonce:
            raise RuntimeError("join request must be sent before join accept")
        parsed = decode_join_accept(phy_payload, self._app_key)
        nwk_s_key, app_s_key = derive_session_keys(
            app_key=self._app_key,
            app_nonce=parsed.app_nonce,
            net_id=parsed.net_id,
            dev_nonce=self.runtime.dev_nonce,
        )
        self.runtime.dev_addr_le = parsed.dev_addr_le
        self.runtime.nwk_s_key = nwk_s_key
        self.runtime.app_s_key = app_s_key
        self.runtime.joined = True
        self.runtime.fcnt_up = 0
        self.runtime.fcnt_down = 0

    def build_data_uplink(self, payload: bytes, f_port: int, confirmed: bool) -> bytes:
        if not self.runtime.joined:
            raise RuntimeError("device is not joined")
        frame = build_unconfirmed_data_up(
            dev_addr_le=self.runtime.dev_addr_le,
            fcnt_up=self.runtime.fcnt_up,
            f_port=f_port,
            frm_payload=payload,
            app_s_key=self.runtime.app_s_key,
            nwk_s_key=self.runtime.nwk_s_key,
            confirmed=confirmed,
        )
        self.runtime.fcnt_up += 1
        return frame
    
    def parse_downlink(self, phy_payload: bytes) -> dict[str, Any]:
        """
        Parse a downlink frame and extract MAC commands.
        
        Args:
            phy_payload: Raw PHYPayload bytes
            
        Returns:
            Dict with parsed downlink information:
            {
                "mtype": int,
                "dev_addr": str,
                "fcnt": int,
                "f_port": int | None,
                "frm_payload": bytes,
                "mac_commands": list[MACCommand],
                "valid_mic": bool,
            }
            
        Raises:
            ValueError: If frame cannot be parsed or MIC is invalid
        """
        if not self.runtime.joined:
            raise RuntimeError("Device must be joined to parse downlinks")
        
        if len(phy_payload) < 12:  # Minimum: MHDR(1) + FHDR(7) + MIC(4)
            raise ValueError(f"Downlink too short: {len(phy_payload)} bytes")
        
        # Parse MHDR
        mhdr = phy_payload[0]
        mtype = (mhdr >> 5) & 0x07
        
        # Parse FHDR
        dev_addr_le = phy_payload[1:5]
        fctrl = phy_payload[5]
        fcnt_bytes = phy_payload[6:8]
        fcnt = int.from_bytes(fcnt_bytes, byteorder="little")
        
        # FOpts length
        f_opts_len = fctrl & 0x0F
        f_opts = phy_payload[8:8 + f_opts_len]
        
        # FPort and FRMPayload
        payload_start = 8 + f_opts_len
        mic_start = len(phy_payload) - 4
        
        f_port = None
        frm_payload = b""
        mac_commands_in_payload = []
        
        if payload_start < mic_start:
            f_port = phy_payload[payload_start]
            frm_payload = phy_payload[payload_start + 1:mic_start]
        
        # Verify MIC
        from lorawan.protocol.crypto_v103 import data_mic
        
        expected_mic = data_mic(
            nwk_s_key=self.runtime.nwk_s_key,
            msg=phy_payload[:mic_start],
            direction=1,  # Downlink
            dev_addr_le=self.runtime.dev_addr_le,
            fcnt=fcnt,
        )
        
        actual_mic = phy_payload[mic_start:]
        valid_mic = (expected_mic == actual_mic)
        
        # Extract MAC commands from FOpts
        mac_commands_in_fopts = self._parse_mac_commands(f_opts)
        
        # If FPort == 0, FRMPayload contains MAC commands
        if f_port == 0 and frm_payload:
            # Decrypt with NwkSKey
            from lorawan.protocol.crypto_v103 import lorawan_payload_cipher
            
            decrypted = lorawan_payload_cipher(
                key=self.runtime.nwk_s_key,
                payload=frm_payload,
                direction=1,  # Downlink
                dev_addr_le=self.runtime.dev_addr_le,
                fcnt=fcnt,
            )
            mac_commands_in_payload = self._parse_mac_commands(decrypted)
        
        all_mac_commands = mac_commands_in_fopts + mac_commands_in_payload
        
        return {
            "mtype": mtype,
            "dev_addr": dev_addr_le[::-1].hex(),
            "fcnt": fcnt,
            "f_port": f_port,
            "frm_payload": frm_payload,
            "mac_commands": all_mac_commands,
            "valid_mic": valid_mic,
        }
    
    def _parse_mac_commands(self, data: bytes) -> list[MACCommand]:
        """Parse MAC commands from byte stream."""
        commands = []
        offset = 0
        
        while offset < len(data):
            if offset >= len(data):
                break
                
            cid = data[offset]
            offset += 1
            
            # Determine payload length based on CID
            # These lengths are for downlink commands (NS → Device)
            payload_lengths = {
                CID_LINK_ADR_REQ: 4,
                CID_DUTY_CYCLE_REQ: 1,
                CID_RX_PARAM_SETUP_REQ: 4,
                CID_DEV_STATUS_REQ: 0,
                CID_NEW_CHANNEL_REQ: 5,
                CID_RX_TIMING_SETUP_REQ: 1,
            }
            
            payload_len = payload_lengths.get(cid, 0)
            
            if offset + payload_len > len(data):
                if self._logger:
                    self._logger.warning(
                        f"Truncated MAC command: CID=0x{cid:02x}, "
                        f"expected {payload_len} bytes, got {len(data) - offset}"
                    )
                break
            
            payload = data[offset:offset + payload_len]
            offset += payload_len
            
            commands.append(MACCommand(cid=cid, payload=payload))
        
        return commands
    
    def apply_mac_commands(self, commands: list[MACCommand]) -> list[MACCommand]:
        """
        Apply MAC commands from Network Server and generate responses.
        
        Args:
            commands: List of MAC commands to process
            
        Returns:
            List of MAC command responses to include in next uplink
        """
        responses = []
        
        for cmd in commands:
            if cmd.cid == CID_LINK_ADR_REQ:
                response = self._apply_link_adr_req(cmd)
                responses.append(response)
                
            elif cmd.cid == CID_RX_PARAM_SETUP_REQ:
                response = self._apply_rx_param_setup_req(cmd)
                responses.append(response)
                
            elif cmd.cid == CID_DEV_STATUS_REQ:
                response = self._apply_dev_status_req(cmd)
                responses.append(response)
                
            elif cmd.cid == CID_NEW_CHANNEL_REQ:
                response = self._apply_new_channel_req(cmd)
                responses.append(response)
                
            elif cmd.cid == CID_DUTY_CYCLE_REQ:
                response = self._apply_duty_cycle_req(cmd)
                responses.append(response)
                
            elif cmd.cid == CID_RX_TIMING_SETUP_REQ:
                response = self._apply_rx_timing_setup_req(cmd)
                responses.append(response)
                
            else:
                if self._logger:
                    self._logger.warning(f"Unknown MAC command CID: 0x{cmd.cid:02x}")
        
        return responses
    
    def _apply_link_adr_req(self, cmd: MACCommand) -> MACCommand:
        """Apply LinkADRReq and return LinkADRAns."""
        if len(cmd.payload) < 4:
            # Invalid payload, reject
            status = 0x00  # All bits 0 = reject
            return MACCommand(cid=CID_LINK_ADR_ANS, payload=bytes([status]))
        
        # Parse LinkADRReq
        data_rate_tx_power = cmd.payload[0]
        data_rate = (data_rate_tx_power >> 4) & 0x0F
        tx_power = data_rate_tx_power & 0x0F
        ch_mask = int.from_bytes(cmd.payload[1:3], byteorder="little")
        redundancy = cmd.payload[3]
        nb_trans = redundancy & 0x0F
        
        # Update device state
        old_state = self.runtime.radio.to_dict()
        self.runtime.radio.data_rate = data_rate
        self.runtime.radio.tx_power = tx_power
        self.runtime.radio.ch_mask = ch_mask
        self.runtime.radio.nb_trans = nb_trans
        
        if self._logger:
            self._logger.info(
                f"Applied LinkADRReq: DR={data_rate}, TXPower={tx_power}, "
                f"ChMask=0x{ch_mask:04x}, NbTrans={nb_trans}",
                extra={"old_radio_state": old_state, "new_radio_state": self.runtime.radio.to_dict()}
            )
        
        # LinkADRAns: 1 byte status (bit 0: power ACK, bit 1: data rate ACK, bit 2: channel mask ACK)
        status = 0x07  # All ACKs set (accept all parameters)
        return MACCommand(cid=CID_LINK_ADR_ANS, payload=bytes([status]))
    
    def _apply_rx_param_setup_req(self, cmd: MACCommand) -> MACCommand:
        """Apply RXParamSetupReq and return RXParamSetupAns."""
        if len(cmd.payload) < 4:
            status = 0x00  # Reject
            return MACCommand(cid=CID_RX_PARAM_SETUP_ANS, payload=bytes([status]))
        
        # Parse RXParamSetupReq
        dl_settings = cmd.payload[0]
        rx1_dr_offset = (dl_settings >> 4) & 0x07
        rx2_data_rate = dl_settings & 0x0F
        frequency = int.from_bytes(cmd.payload[1:4], byteorder="little")
        
        # Update device state
        self.runtime.radio.rx1_dr_offset = rx1_dr_offset
        self.runtime.radio.rx2_data_rate = rx2_data_rate
        
        if self._logger:
            self._logger.info(
                f"Applied RXParamSetupReq: RX1DRoffset={rx1_dr_offset}, "
                f"RX2DataRate={rx2_data_rate}, Frequency={frequency}Hz"
            )
        
        # RXParamSetupAns: 1 byte status
        status = 0x07  # All bits set (channel ACK, RX2 data rate ACK, RX1DRoffset ACK)
        return MACCommand(cid=CID_RX_PARAM_SETUP_ANS, payload=bytes([status]))
    
    def _apply_dev_status_req(self, cmd: MACCommand) -> MACCommand:
        """Apply DevStatusReq and return DevStatusAns."""
        # DevStatusAns: 2 bytes (battery, margin)
        battery = 255  # External power
        margin = 20    # Link margin in dB (dummy value)
        
        if self._logger:
            self._logger.debug("Responding to DevStatusReq")
        
        return MACCommand(cid=CID_DEV_STATUS_ANS, payload=bytes([battery, margin]))
    
    def _apply_new_channel_req(self, cmd: MACCommand) -> MACCommand:
        """Apply NewChannelReq and return NewChannelAns."""
        if len(cmd.payload) < 5:
            status = 0x00  # Reject
            return MACCommand(cid=CID_NEW_CHANNEL_ANS, payload=bytes([status]))
        
        # For now, accept but don't modify channels
        if self._logger:
            self._logger.info("Received NewChannelReq (accepted but not applied)")
        
        status = 0x03  # Both bits set (channel frequency OK, data rate range OK)
        return MACCommand(cid=CID_NEW_CHANNEL_ANS, payload=bytes([status]))
    
    def _apply_duty_cycle_req(self, cmd: MACCommand) -> MACCommand:
        """Apply DutyCycleReq and return DutyCycleAns."""
        if len(cmd.payload) < 1:
            return MACCommand(cid=CID_DUTY_CYCLE_ANS, payload=b"")
        
        max_duty_cycle = cmd.payload[0]
        self.runtime.radio.duty_cycle = max_duty_cycle
        
        if self._logger:
            self._logger.info(f"Applied DutyCycleReq: MaxDCycle={max_duty_cycle}")
        
        return MACCommand(cid=CID_DUTY_CYCLE_ANS, payload=b"")
    
    def _apply_rx_timing_setup_req(self, cmd: MACCommand) -> MACCommand:
        """Apply RXTimingSetupReq and return RXTimingSetupAns."""
        if len(cmd.payload) < 1:
            return MACCommand(cid=CID_RX_TIMING_SETUP_ANS, payload=b"")
        
        delay = cmd.payload[0] & 0x0F
        self.runtime.radio.rx1_delay = delay if delay > 0 else 1  # 0 means 1 second
        
        if self._logger:
            self._logger.info(f"Applied RXTimingSetupReq: RX1Delay={self.runtime.radio.rx1_delay}s")
        
        return MACCommand(cid=CID_RX_TIMING_SETUP_ANS, payload=b"")
