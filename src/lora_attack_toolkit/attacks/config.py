"""Attack configuration data structures."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AttackConfig:
    """
    Basic attack metadata configuration.
    
    This is the minimal config needed for attack orchestration.
    Attack-specific configuration should use typed dataclasses
    from schema_v1.py (ReplayConfigV1, JoinReplayConfigV1, etc.)
    """
    
    name: str
    description: str
    timeout_sec: float = 60.0
    capture_enabled: bool = True
