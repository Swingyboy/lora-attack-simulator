"""Attack result data structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackResult:
    """Result of attack execution.
    
    Stable contract for attack outputs, consumed by:
    - CLI/shell for display
    - Result persistence (JSON files)
    - Metrics collection
    - Test assertions
    
    This is the stable interface between attacks and the framework.
    Changes here affect all consumers.
    """
    
    attack_name: str
    attack_type: str
    success: bool
    message: str
    metrics: dict[str, Any] = field(default_factory=dict)
    
    # Optional detailed results
    captured_packets: int = 0
    validation_summary: str | None = None
    criteria_met: dict[str, bool] | None = None
    error: str | None = None
    interrupted: bool = False
    
    # Metadata
    duration_sec: float | None = None
    timestamp: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for JSON serialization.
        
        Returns stable output format that won't break result files.
        """
        result = {
            "attack_name": self.attack_name,
            "attack_type": self.attack_type,
            "success": self.success,
            "message": self.message,
            "metrics": self.metrics,
        }
        
        if self.captured_packets > 0:
            result["captured_packets"] = self.captured_packets
        
        if self.validation_summary:
            result["validation_summary"] = self.validation_summary
        
        if self.criteria_met:
            result["criteria_met"] = self.criteria_met
        
        if self.error:
            result["error"] = self.error
        
        if self.interrupted:
            result["interrupted"] = True
        
        if self.duration_sec is not None:
            result["duration_sec"] = self.duration_sec
        
        if self.timestamp:
            result["timestamp"] = self.timestamp
        
        return result
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackResult:
        """Create from dict (for deserialization if needed)."""
        return cls(
            attack_name=data["attack_name"],
            attack_type=data["attack_type"],
            success=data["success"],
            message=data["message"],
            metrics=data.get("metrics", {}),
            captured_packets=data.get("captured_packets", 0),
            validation_summary=data.get("validation_summary"),
            criteria_met=data.get("criteria_met"),
            error=data.get("error"),
            interrupted=data.get("interrupted", False),
            duration_sec=data.get("duration_sec"),
            timestamp=data.get("timestamp"),
        )
