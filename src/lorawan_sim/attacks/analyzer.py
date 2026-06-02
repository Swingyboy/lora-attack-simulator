"""Attack response analysis utilities."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lorawan_sim.attacks.packet_capture import PacketCapture


class AttackAnalyzer(ABC):
    """
    Abstract base class for attack result analysis.
    
    Analyzes captured packets and Network Server responses
    to determine attack success and extract metrics.
    """
    
    @abstractmethod
    def analyze(self, capture: PacketCapture) -> dict[str, Any]:
        """
        Analyze captured packets and determine attack outcome.
        
        Args:
            capture: PacketCapture instance with captured traffic
        
        Returns:
            Dictionary with:
                - success: bool indicating attack success
                - message: str describing the result
                - metrics: dict with attack-specific metrics
        """
        raise NotImplementedError
