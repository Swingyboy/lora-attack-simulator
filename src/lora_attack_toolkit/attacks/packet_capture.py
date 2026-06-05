"""Packet capture utilities for attack simulation."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from logging import Logger


@dataclass
class CapturedPacket:
    """Captured LoRaWAN packet with metadata."""
    
    timestamp: float
    phy_payload: bytes
    fcnt: int | None = None
    packet_type: str = "unknown"  # "join_request", "join_accept", "data_up", "data_down"
    metadata: dict = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        if self.timestamp == 0:
            self.timestamp = time.time()


class PacketCapture:
    """
    Captures LoRaWAN packets during attack execution.
    
    Stores uplinks and downlinks with timestamps and metadata
    for later replay and analysis.
    """
    
    def __init__(self, logger: Logger) -> None:
        self.logger = logger
        self.uplinks: list[CapturedPacket] = []
        self.downlinks: list[CapturedPacket] = []
        self.metadata: dict = {}
        self._enabled = True
    
    def enable(self) -> None:
        """Enable packet capture."""
        self._enabled = True
        self.logger.debug("Packet capture enabled")
    
    def disable(self) -> None:
        """Disable packet capture."""
        self._enabled = False
        self.logger.debug("Packet capture disabled")
    
    def capture_uplink(
        self,
        phy_payload: bytes,
        fcnt: int | None = None,
        packet_type: str = "data_up",
        metadata: dict | None = None,
    ) -> CapturedPacket:
        """Capture an uplink packet."""
        if not self._enabled:
            return CapturedPacket(
                timestamp=time.time(),
                phy_payload=phy_payload,
                fcnt=fcnt,
                packet_type=packet_type,
                metadata=metadata or {},
            )
        
        packet = CapturedPacket(
            timestamp=time.time(),
            phy_payload=phy_payload,
            fcnt=fcnt,
            packet_type=packet_type,
            metadata=metadata or {},
        )
        
        self.uplinks.append(packet)
        
        self.logger.debug(
            f"Captured uplink: type={packet_type}, fcnt={fcnt}",
            extra={
                "packet_type": packet_type,
                "fcnt": fcnt,
                "payload_len": len(phy_payload),
            },
        )
        
        return packet
    
    def capture_downlink(
        self,
        phy_payload: bytes,
        fcnt: int | None = None,
        packet_type: str = "data_down",
        metadata: dict | None = None,
    ) -> CapturedPacket:
        """Capture a downlink packet."""
        if not self._enabled:
            return CapturedPacket(
                timestamp=time.time(),
                phy_payload=phy_payload,
                fcnt=fcnt,
                packet_type=packet_type,
                metadata=metadata or {},
            )
        
        packet = CapturedPacket(
            timestamp=time.time(),
            phy_payload=phy_payload,
            fcnt=fcnt,
            packet_type=packet_type,
            metadata=metadata or {},
        )
        
        self.downlinks.append(packet)
        
        self.logger.debug(
            f"Captured downlink: type={packet_type}, fcnt={fcnt}",
            extra={
                "packet_type": packet_type,
                "fcnt": fcnt,
                "payload_len": len(phy_payload),
            },
        )
        
        return packet
    
    def get_last_uplink(self, packet_type: str | None = None) -> CapturedPacket | None:
        """Get the last captured uplink, optionally filtered by type."""
        if not self.uplinks:
            return None
        
        if packet_type:
            for packet in reversed(self.uplinks):
                if packet.packet_type == packet_type:
                    return packet
            return None
        
        return self.uplinks[-1]
    
    def get_last_downlink(self, packet_type: str | None = None) -> CapturedPacket | None:
        """Get the last captured downlink, optionally filtered by type."""
        if not self.downlinks:
            return None
        
        if packet_type:
            for packet in reversed(self.downlinks):
                if packet.packet_type == packet_type:
                    return packet
            return None
        
        return self.downlinks[-1]
    
    def clear(self) -> None:
        """Clear all captured packets."""
        self.uplinks.clear()
        self.downlinks.clear()
        self.logger.debug("Packet capture cleared")
    
    def get_stats(self) -> dict:
        """Get capture statistics."""
        return {
            "total_uplinks": len(self.uplinks),
            "total_downlinks": len(self.downlinks),
            "uplink_types": self._count_by_type(self.uplinks),
            "downlink_types": self._count_by_type(self.downlinks),
        }
    
    def _count_by_type(self, packets: list[CapturedPacket]) -> dict[str, int]:
        """Count packets by type."""
        counts: dict[str, int] = {}
        for packet in packets:
            counts[packet.packet_type] = counts.get(packet.packet_type, 0) + 1
        return counts
