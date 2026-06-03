"""Session management for the LoRaWAN simulator CLI.

This module provides a centralized session model that tracks CLI state,
loaded scenarios, and runtime configuration.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class Session:
    """Represents a CLI session with loaded scenario and configuration.
    
    A session tracks:
    - Unique session ID for log correlation
    - Loaded scenario and metadata
    - Runtime configuration overrides
    - Session lifecycle timestamps
    """
    
    # Session identification
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    started_at: datetime = field(default_factory=datetime.now)
    
    # Loaded scenario
    scenario_name: str | None = None
    scenario_path: Path | None = None
    scenario_data: dict[str, Any] | None = None
    
    # Runtime overrides (parameters changed via 'set' command)
    runtime_overrides: dict[str, Any] = field(default_factory=dict)
    
    # Logging configuration
    log_level: str = "INFO"
    log_file: Path | None = None
    
    def is_scenario_loaded(self) -> bool:
        """Check if a scenario is currently loaded."""
        return self.scenario_data is not None
    
    def load_scenario(
        self,
        name: str,
        path: Path,
        data: dict[str, Any]
    ) -> None:
        """Load a scenario into the session.
        
        Args:
            name: Scenario identifier
            path: Path to scenario file
            data: Parsed scenario JSON
        """
        self.scenario_name = name
        self.scenario_path = path
        self.scenario_data = data
        self.runtime_overrides.clear()
    
    def clear_scenario(self) -> None:
        """Clear the currently loaded scenario."""
        self.scenario_name = None
        self.scenario_path = None
        self.scenario_data = None
        self.runtime_overrides.clear()
    
    def set_parameter(self, key: str, value: Any) -> None:
        """Record a runtime parameter override.
        
        Args:
            key: Parameter path (e.g., 'target.host')
            value: New value
        """
        self.runtime_overrides[key] = value
    
    def reset_parameter(self, key: str) -> None:
        """Remove a runtime parameter override.
        
        Args:
            key: Parameter path to reset
        """
        self.runtime_overrides.pop(key, None)
    
    def reset_all_parameters(self) -> None:
        """Remove all runtime parameter overrides."""
        self.runtime_overrides.clear()
    
    def get_effective_scenario(self) -> dict[str, Any] | None:
        """Get scenario data with runtime overrides applied.
        
        Returns:
            Scenario dict with overrides, or None if no scenario loaded
        """
        if not self.scenario_data:
            return None
        
        # For now, return original data
        # TODO: Deep merge runtime_overrides into scenario_data
        return self.scenario_data
    
    def __repr__(self) -> str:
        """String representation of session state."""
        return (
            f"Session(id={self.session_id}, "
            f"scenario={self.scenario_name or 'None'}, "
            f"overrides={len(self.runtime_overrides)})"
        )
