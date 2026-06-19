"""Attack result data structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ExecutionStatus(str, Enum):
    """Technical execution outcome — did the attack machinery run to completion?"""

    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class SecurityVerdict(str, Enum):
    """Security assessment of the target — how did the NS behave?"""

    SECURE = "secure"
    VULNERABLE = "vulnerable"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"


class Confidence(str, Enum):
    """Confidence in the :attr:`SecurityVerdict`."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AttackResult:
    """Result of attack execution.

    Stable contract for attack outputs, consumed by:
    - CLI/shell for display
    - Result persistence (JSON files)
    - Metrics collection
    - Test assertions

    Standardized fields
    -------------------
    ``execution_status``
        Whether the attack machinery completed, was cancelled, or failed.
    ``security_verdict``
        Protocol-level assessment of the target's behaviour.
    ``target_protected``
        ``True`` when the NS behaved correctly (defended against the attack),
        ``False`` when it showed a potential weakness, ``None`` when unknown.
    ``confidence``
        Reliability of the ``security_verdict``.

    Compatibility
    -------------
    The legacy ``success`` field is retained as a read-only property that maps
    to ``execution_status == COMPLETED``.  Use the new fields in all new code.
    """

    attack_name: str
    attack_type: str
    message: str

    # ── New standardized fields ──────────────────────────────────────────────
    execution_status: ExecutionStatus = ExecutionStatus.COMPLETED
    security_verdict: SecurityVerdict = SecurityVerdict.INCONCLUSIVE
    target_protected: bool | None = None
    confidence: Confidence = Confidence.LOW

    # ── Optional detailed results ────────────────────────────────────────────
    metrics: dict[str, Any] = field(default_factory=dict)
    captured_packets: int = 0
    validation_summary: str | None = None
    criteria_met: dict[str, bool] | None = None
    error: str | None = None
    interrupted: bool = False

    # ── Metadata ─────────────────────────────────────────────────────────────
    duration_sec: float | None = None
    timestamp: str | None = None

    # ── Legacy compat ─────────────────────────────────────────────────────────
    # Callers may still pass success= as a keyword; store it to avoid breaking
    # old construction sites while migration is in progress.
    _success_override: bool | None = field(default=None, repr=False, compare=False)

    @property
    def success(self) -> bool:
        """Legacy compatibility accessor.

        Returns the explicit override when set, otherwise maps
        ``execution_status == COMPLETED`` to ``True``.
        """
        if self._success_override is not None:
            return self._success_override
        return self.execution_status == ExecutionStatus.COMPLETED

    @success.setter
    def success(self, value: bool) -> None:
        self._success_override = value

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for JSON serialization."""
        result: dict[str, Any] = {
            "attack_name": self.attack_name,
            "attack_type": self.attack_type,
            "execution_status": self.execution_status.value,
            "security_verdict": self.security_verdict.value,
            "confidence": self.confidence.value,
            "message": self.message,
            "metrics": self.metrics,
            # Legacy field kept for backward compat with consumers reading JSON
            "success": self.success,
        }

        if self.target_protected is not None:
            result["target_protected"] = self.target_protected

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
        """Create from dict (for deserialization)."""
        r = cls(
            attack_name=data["attack_name"],
            attack_type=data["attack_type"],
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
        if "execution_status" in data:
            r.execution_status = ExecutionStatus(data["execution_status"])
        if "security_verdict" in data:
            r.security_verdict = SecurityVerdict(data["security_verdict"])
        if "confidence" in data:
            r.confidence = Confidence(data["confidence"])
        if "target_protected" in data:
            r.target_protected = data["target_protected"]
        # Honour legacy success field when new fields are absent
        if "success" in data and "execution_status" not in data:
            r._success_override = bool(data["success"])
        return r

    @classmethod
    def failed(
        cls,
        attack_name: str,
        attack_type: str,
        error: str,
        message: str | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> "AttackResult":
        """Convenience constructor for failed execution results."""
        return cls(
            attack_name=attack_name,
            attack_type=attack_type,
            message=message or f"Attack execution failed: {error}",
            execution_status=ExecutionStatus.FAILED,
            security_verdict=SecurityVerdict.INCONCLUSIVE,
            confidence=Confidence.LOW,
            metrics=metrics or {},
            error=error,
        )
