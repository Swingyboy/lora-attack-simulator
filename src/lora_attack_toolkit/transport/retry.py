"""Retry and backoff policy for transport resilience."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RetryPolicy:
    """Configuration for transport-level retry and exponential backoff.

    These values are internal implementation details and are **not** exposed
    in user-facing scenario configuration.

    Attributes:
        enabled:            Whether retry/recovery is active.  Set to ``False``
                            in tests that want predictable single-attempt behaviour.
        max_attempts:       Number of *recovery* attempts after the initial
                            failure.  Total operation attempts = max_attempts + 1.
        initial_delay_sec:  Delay (seconds) before the first recovery attempt.
        backoff_multiplier: Factor applied to the delay after each failed attempt
                            (exponential backoff).
    """

    enabled: bool = True
    max_attempts: int = 3
    initial_delay_sec: float = 2.0
    backoff_multiplier: float = 2.0
