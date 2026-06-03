"""Attack response analysis utilities."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lorawan_sim.attacks.packet_capture import PacketCapture
    from lorawan_sim.domain.attack_scenario.schema_v1 import ExpectedBehavior


class AttackAnalyzer(ABC):
    """
    Abstract base class for attack result analysis.
    
    Analyzes captured packets and Network Server responses
    to determine attack success and extract metrics.
    """
    
    @abstractmethod
    def analyze(
        self, capture: PacketCapture, expected: ExpectedBehavior | None = None
    ) -> dict[str, Any]:
        """
        Analyze captured packets and determine attack outcome.
        
        Args:
            capture: PacketCapture instance with captured traffic
            expected: Optional expected behavior and success criteria for validation
        
        Returns:
            Dictionary with:
                - success: bool indicating attack execution success
                - message: str describing the result
                - metrics: dict with attack-specific metrics
                - criteria_met: dict mapping criterion → passed/failed (if expected provided)
                - validation_summary: str describing security posture (if expected provided)
        """
        raise NotImplementedError
