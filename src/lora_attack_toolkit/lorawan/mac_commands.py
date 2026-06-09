"""LoRaWAN MAC command utilities for attack scenarios."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# MAC Command CIDs (Command Identifiers) - LoRaWAN 1.0.3
CID_LINK_CHECK_REQ = 0x02
CID_LINK_CHECK_ANS = 0x02
CID_LINK_ADR_REQ = 0x03
CID_LINK_ADR_ANS = 0x03
CID_DUTY_CYCLE_REQ = 0x04
CID_DUTY_CYCLE_ANS = 0x04
CID_RX_PARAM_SETUP_REQ = 0x05
CID_RX_PARAM_SETUP_ANS = 0x05
CID_DEV_STATUS_REQ = 0x06
CID_DEV_STATUS_ANS = 0x06
CID_NEW_CHANNEL_REQ = 0x07
CID_NEW_CHANNEL_ANS = 0x07
CID_RX_TIMING_SETUP_REQ = 0x08
CID_RX_TIMING_SETUP_ANS = 0x08


@dataclass(frozen=True)
class MACCommand:
    """Represents a MAC command with CID and payload."""
    
    cid: int
    payload: bytes
    
    def to_bytes(self) -> bytes:
        """Convert MAC command to bytes."""
        return bytes([self.cid]) + self.payload
    
    def __len__(self) -> int:
        """Return total length of MAC command."""
        return 1 + len(self.payload)


def build_link_adr_req(
    data_rate: int = 0,
    tx_power: int = 0,
    ch_mask: int = 0x00FF,
    redundancy: int = 0,
) -> MACCommand:
    """
    Build LinkADRReq MAC command.
    
    Used by Network Server to adjust device data rate, TX power, and channels.
    
    Args:
        data_rate: Data rate (0-15, 4 bits)
        tx_power: TX power (0-15, 4 bits)
        ch_mask: Channel mask (16 bits)
        redundancy: NbTrans and ChMaskCntl (8 bits)
    
    Returns:
        MACCommand instance
    
    Payload format (4 bytes):
    - Byte 0: DataRate_TXPower (DR: bits 7-4, TXPower: bits 3-0)
    - Byte 1-2: ChMask (16 bits, little-endian)
    - Byte 3: Redundancy (NbTrans: bits 3-0, ChMaskCntl: bits 6-4, RFU: bit 7)
    """
    # Combine data rate and TX power
    data_rate_tx_power = ((data_rate & 0x0F) << 4) | (tx_power & 0x0F)
    
    # Convert channel mask to little-endian 2 bytes
    ch_mask_le = ch_mask.to_bytes(2, byteorder="little")
    
    # Redundancy byte
    redundancy_byte = redundancy & 0xFF
    
    payload = bytes([data_rate_tx_power]) + ch_mask_le + bytes([redundancy_byte])
    
    return MACCommand(cid=CID_LINK_ADR_REQ, payload=payload)


def build_rx_param_setup_req(
    rx1_dr_offset: int = 0,
    rx2_data_rate: int = 0,
    frequency: int = 869525000,
) -> MACCommand:
    """
    Build RXParamSetupReq MAC command.
    
    Used by Network Server to modify RX1 and RX2 parameters.
    
    Args:
        rx1_dr_offset: RX1 data rate offset (0-7, 3 bits)
        rx2_data_rate: RX2 data rate (0-15, 4 bits)
        frequency: RX2 frequency in Hz (24 bits, 100 Hz resolution)
    
    Returns:
        MACCommand instance
    
    Payload format (4 bytes):
    - Byte 0: DLSettings (RFU: bit 7, RX1DRoffset: bits 6-4, RX2DataRate: bits 3-0)
    - Byte 1-3: Frequency (24 bits, little-endian, in 100 Hz units)
    """
    # Combine RX1 DR offset and RX2 data rate
    dl_settings = ((rx1_dr_offset & 0x07) << 4) | (rx2_data_rate & 0x0F)
    
    # Convert frequency to 100 Hz units (24 bits)
    freq_100hz = frequency // 100
    freq_bytes = freq_100hz.to_bytes(3, byteorder="little")
    
    payload = bytes([dl_settings]) + freq_bytes
    
    return MACCommand(cid=CID_RX_PARAM_SETUP_REQ, payload=payload)


def build_new_channel_req(
    ch_index: int = 3,
    frequency: int = 867100000,
    max_dr: int = 5,
    min_dr: int = 0,
) -> MACCommand:
    """
    Build NewChannelReq MAC command.
    
    Used by Network Server to add or modify a channel.
    
    Args:
        ch_index: Channel index (0-15)
        frequency: Channel frequency in Hz (24 bits, 100 Hz resolution)
        max_dr: Maximum data rate (0-15, 4 bits)
        min_dr: Minimum data rate (0-15, 4 bits)
    
    Returns:
        MACCommand instance
    
    Payload format (5 bytes):
    - Byte 0: ChIndex (channel index)
    - Byte 1-3: Freq (24 bits, little-endian, in 100 Hz units)
    - Byte 4: DrRange (MaxDR: bits 7-4, MinDR: bits 3-0)
    """
    # Convert frequency to 100 Hz units
    freq_100hz = frequency // 100
    freq_bytes = freq_100hz.to_bytes(3, byteorder="little")
    
    # Combine max and min data rates
    dr_range = ((max_dr & 0x0F) << 4) | (min_dr & 0x0F)
    
    payload = bytes([ch_index & 0xFF]) + freq_bytes + bytes([dr_range])
    
    return MACCommand(cid=CID_NEW_CHANNEL_REQ, payload=payload)


def build_dev_status_req() -> MACCommand:
    """
    Build DevStatusReq MAC command.
    
    Used by Network Server to request device battery level and demodulation margin.
    
    Returns:
        MACCommand instance
    
    Payload format: No payload (0 bytes)
    """
    return MACCommand(cid=CID_DEV_STATUS_REQ, payload=b"")


def build_duty_cycle_req(max_duty_cycle: int = 0) -> MACCommand:
    """
    Build DutyCycleReq MAC command.
    
    Used by Network Server to limit device transmit duty cycle.
    
    Args:
        max_duty_cycle: MaxDCycle (0-15), where duty cycle = 1 / (2^MaxDCycle)
    
    Returns:
        MACCommand instance
    
    Payload format (1 byte):
    - Byte 0: MaxDCycle (bits 3-0), RFU (bits 7-4)
    """
    payload = bytes([max_duty_cycle & 0x0F])
    return MACCommand(cid=CID_DUTY_CYCLE_REQ, payload=payload)


def build_rx_timing_setup_req(delay: int = 1) -> MACCommand:
    """
    Build RXTimingSetupReq MAC command.
    
    Used by Network Server to modify RX slot timing.
    
    Args:
        delay: Delay in seconds (0-15), where actual delay = Delay + 1
    
    Returns:
        MACCommand instance
    
    Payload format (1 byte):
    - Byte 0: Settings (Delay: bits 3-0, RFU: bits 7-4)
    """
    payload = bytes([delay & 0x0F])
    return MACCommand(cid=CID_RX_TIMING_SETUP_REQ, payload=payload)


def build_malformed_mac_command(
    cid: int,
    malformation_type: str = "truncated",
    **kwargs: Any,
) -> MACCommand:
    """
    Build malformed MAC command for attack scenarios.
    
    Args:
        cid: Command identifier
        malformation_type: Type of malformation:
            - "truncated": Payload too short
            - "oversized": Payload too long
            - "invalid_values": Out-of-range parameter values
            - "corrupted": Random bit flips
        **kwargs: Additional parameters for specific malformations
    
    Returns:
        MACCommand instance with malformed payload
    """
    if malformation_type == "truncated":
        # Create truncated payload (1 byte less than expected)
        if cid == CID_LINK_ADR_REQ:
            # LinkADRReq expects 4 bytes, provide 3
            payload = b"\x00\x00\x00"
        elif cid == CID_RX_PARAM_SETUP_REQ:
            # RXParamSetupReq expects 4 bytes, provide 2
            payload = b"\x00\x00"
        elif cid == CID_NEW_CHANNEL_REQ:
            # NewChannelReq expects 5 bytes, provide 3
            payload = b"\x00\x00\x00"
        else:
            # Generic truncated payload
            payload = b"\x00"
    
    elif malformation_type == "oversized":
        # Create oversized payload (extra bytes)
        if cid == CID_LINK_ADR_REQ:
            # LinkADRReq expects 4 bytes, provide 8
            payload = b"\x00\x00\x00\x00\xFF\xFF\xFF\xFF"
        elif cid == CID_DEV_STATUS_REQ:
            # DevStatusReq expects 0 bytes, provide 4
            payload = b"\x00\x00\x00\x00"
        else:
            # Generic oversized payload
            payload = b"\x00" * 10
    
    elif malformation_type == "invalid_values":
        # Create payload with out-of-range values
        if cid == CID_LINK_ADR_REQ:
            # Invalid data rate (15), invalid TX power (15), all channels disabled
            payload = b"\xFF\x00\x00\xFF"
        elif cid == CID_RX_PARAM_SETUP_REQ:
            # Invalid RX1 DR offset (7), invalid RX2 DR (15), invalid frequency
            payload = b"\x7F\xFF\xFF\xFF"
        elif cid == CID_NEW_CHANNEL_REQ:
            # Invalid channel index (255), invalid frequency, invalid DR range
            payload = b"\xFF\xFF\xFF\xFF\xFF"
        else:
            # Generic invalid values
            payload = b"\xFF" * 4
    
    elif malformation_type == "corrupted":
        # Create payload with random corruption
        import secrets
        length = kwargs.get("length", 4)
        payload = secrets.token_bytes(length)
    
    else:
        raise ValueError(f"Unknown malformation type: {malformation_type}")
    
    return MACCommand(cid=cid, payload=payload)


def encode_mac_commands(commands: list[MACCommand]) -> bytes:
    """
    Encode multiple MAC commands into FOpts field.
    
    Args:
        commands: List of MACCommand instances
    
    Returns:
        Encoded MAC commands as bytes
    """
    result = b""
    for cmd in commands:
        result += cmd.to_bytes()
    return result


def parse_mac_command(data: bytes) -> tuple[MACCommand | None, int]:
    """
    Parse a single MAC command from byte stream.
    
    Args:
        data: Byte stream starting with MAC command
    
    Returns:
        Tuple of (MACCommand instance or None, bytes consumed)
    """
    if len(data) < 1:
        return None, 0
    
    cid = data[0]
    
    # Determine expected payload length based on CID
    if cid == CID_LINK_ADR_REQ:
        payload_len = 4
    elif cid == CID_RX_PARAM_SETUP_REQ:
        payload_len = 4
    elif cid == CID_NEW_CHANNEL_REQ:
        payload_len = 5
    elif cid == CID_DEV_STATUS_REQ:
        payload_len = 0
    elif cid == CID_DUTY_CYCLE_REQ:
        payload_len = 1
    elif cid == CID_RX_TIMING_SETUP_REQ:
        payload_len = 1
    else:
        # Unknown CID, cannot parse
        return None, 1
    
    total_len = 1 + payload_len
    if len(data) < total_len:
        # Truncated command
        return None, len(data)
    
    payload = data[1:total_len]
    return MACCommand(cid=cid, payload=payload), total_len
