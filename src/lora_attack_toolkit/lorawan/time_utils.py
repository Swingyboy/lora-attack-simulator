"""Unified time utilities for LoRaWAN simulation.

Responsibilities
----------------
* GPS ↔ Unix timestamp conversion with leap-second correction.
* Injectable :class:`SimClock` protocol so attack and analysis code never
  calls ``time.time()`` or ``time.monotonic()`` directly — making all
  time-dependent logic deterministic in tests.
* Cooperative cancellable sleep (:func:`interruptible_sleep`).

GPS epoch background
--------------------
The GPS epoch started on 1980-01-06 00:00:00 UTC.  GPS time is a continuous
atomic timescale and does not insert leap seconds; as a result it diverges from
UTC by one second every time a new leap second is added.

Conversion::

    gps_time = (unix_time - GPS_EPOCH_UNIX) + GPS_LEAP_SECONDS
    unix_time = gps_time  - GPS_LEAP_SECONDS + GPS_EPOCH_UNIX

As of the 2017 IERS bulletin, the GPS–UTC offset is **18 seconds**
(GPS is 18 s ahead of UTC).  This value is embedded as a module constant and
should be updated when the IERS announces a new leap second.

``DeviceTimeAns`` payload (LoRaWAN 1.0.3 §5.9) carries **GPS seconds** in the
lower 4 bytes and a sub-second fractional in the 5th byte (1/256 s resolution).
Use :func:`gps_to_unix` to compare those values against wall-clock timestamps.
"""

from __future__ import annotations

import threading as _threading
import time as _time
from typing import Optional, Protocol, runtime_checkable

# ── GPS / Unix conversion constants ──────────────────────────────────────────

#: Unix timestamp of the GPS epoch (1980-01-06 00:00:00 UTC).
GPS_EPOCH_UNIX: int = 315_964_800

#: Number of leap seconds accumulated since the GPS epoch (as of 2017-01-01).
#: Update this constant when the IERS announces a new leap second.
GPS_LEAP_SECONDS: int = 18


def unix_to_gps(unix_time: float) -> float:
    """Convert a Unix timestamp to GPS seconds since the GPS epoch.

    Args:
        unix_time: Seconds since 1970-01-01 00:00:00 UTC (Unix epoch).

    Returns:
        Seconds since 1980-01-06 00:00:00 (GPS epoch, no leap seconds).

    Example::

        >>> unix_to_gps(1_700_000_000)  # some Unix timestamp in 2023
        1384035218.0
    """
    return (unix_time - GPS_EPOCH_UNIX) + GPS_LEAP_SECONDS


def gps_to_unix(gps_time: float) -> float:
    """Convert GPS seconds (since GPS epoch) to a Unix timestamp.

    Args:
        gps_time: Seconds since 1980-01-06 00:00:00 (GPS epoch).

    Returns:
        Seconds since 1970-01-01 00:00:00 UTC (Unix epoch).
    """
    return (gps_time - GPS_LEAP_SECONDS) + GPS_EPOCH_UNIX


# ── Injectable clock protocol ─────────────────────────────────────────────────


@runtime_checkable
class SimClock(Protocol):
    """Injectable time source for replay / forgery analysis code.

    Providing a :class:`FakeClock` in tests eliminates all real-time
    dependencies so tests run deterministically at full speed.

    Production code uses the :class:`WallClock` singleton which delegates
    to the Python :mod:`time` module.
    """

    def monotonic(self) -> float:
        """Return a monotonically increasing float (seconds).

        Must never go backward; suitable for measuring intervals.
        """
        ...

    def unix_time(self) -> float:
        """Return the current wall-clock time as a Unix timestamp (seconds)."""
        ...

    def gps_time(self) -> float:
        """Return the current time expressed as GPS seconds since the GPS epoch.

        Derived from :meth:`unix_time` via :func:`unix_to_gps`.
        """
        ...

    def sleep(
        self, seconds: float, cancel_event: Optional["_threading.Event"] = None
    ) -> bool:
        """Sleep for *seconds*, returning ``True`` if the full duration elapsed.

        Returns ``False`` when *cancel_event* is set before the duration
        expires. Implementations must keep :meth:`monotonic` consistent with the
        elapsed sleep so attack timing logic remains coherent under a fake clock.
        """
        ...


class WallClock:
    """Production clock backed by :mod:`time`."""

    def monotonic(self) -> float:
        return _time.monotonic()

    def unix_time(self) -> float:
        return _time.time()

    def gps_time(self) -> float:
        return unix_to_gps(_time.time())

    def sleep(
        self, seconds: float, cancel_event: Optional["_threading.Event"] = None
    ) -> bool:
        return interruptible_sleep(seconds, cancel_event)


class FakeClock:
    """Deterministic clock for unit tests.

    Args:
        start_unix: Initial Unix timestamp (default: GPS epoch so GPS time
            starts at 0 for easy arithmetic in tests).
        start_mono: Initial monotonic value (default: 0.0).

    Usage::

        clock = FakeClock(start_unix=1_700_000_000.0, start_mono=0.0)
        clock.advance(1.5)   # advance both clocks by 1.5 s
        clock.advance_mono(0.5)  # advance monotonic only
    """

    def __init__(
        self,
        start_unix: float = float(GPS_EPOCH_UNIX),
        start_mono: float = 0.0,
    ) -> None:
        self._unix = start_unix
        self._mono = start_mono
        self._lock = _threading.Lock()

    # ---- SimClock interface ----

    def monotonic(self) -> float:
        return self._mono

    def unix_time(self) -> float:
        return self._unix

    def gps_time(self) -> float:
        return unix_to_gps(self._unix)

    def sleep(
        self, seconds: float, cancel_event: Optional["_threading.Event"] = None
    ) -> bool:
        """Advance the fake clock by *seconds* without blocking.

        Honours *cancel_event* (returns ``False`` if it is set) so cancellation
        paths behave the same as :class:`WallClock`, while keeping unit tests
        instantaneous and deterministic.
        """
        if cancel_event is not None and cancel_event.is_set():
            return False
        if seconds > 0:
            self.advance(seconds)
        return not (cancel_event is not None and cancel_event.is_set())

    # ---- Mutation helpers ----

    def advance(self, seconds: float) -> None:
        """Advance both the monotonic and Unix clocks by *seconds*."""
        with self._lock:
            self._mono += seconds
            self._unix += seconds

    def advance_mono(self, seconds: float) -> None:
        """Advance the monotonic clock only (simulates monotonic drift)."""
        with self._lock:
            self._mono += seconds

    def set_unix(self, unix_time: float) -> None:
        """Set the Unix clock to an absolute value."""
        self._unix = unix_time

    def set_mono(self, mono: float) -> None:
        """Set the monotonic clock to an absolute value."""
        self._mono = mono


#: Global default clock — replace in tests via dependency injection.
_default_wall_clock = WallClock()


def interruptible_sleep(
    seconds: float,
    cancel_event: Optional["_threading.Event"] = None,
    *,
    poll_interval_sec: float = 0.05,
) -> bool:
    """Sleep for *seconds*, waking early if *cancel_event* is set.

    Args:
        seconds: Duration to sleep.
        cancel_event: Optional threading.Event; when set the sleep aborts.
        poll_interval_sec: How often to check the cancel_event (seconds).

    Returns:
        ``True`` if the full duration elapsed normally.
        ``False`` if *cancel_event* was set before the duration expired.

    When *cancel_event* is ``None`` the function behaves like
    ``time.sleep(seconds)`` and always returns ``True``.
    """
    if cancel_event is None:
        _time.sleep(seconds)
        return True
    if seconds <= 0:
        return not cancel_event.is_set()
    deadline = _time.monotonic() + seconds
    while True:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            break
        wait_time = min(poll_interval_sec, remaining)
        if cancel_event.wait(timeout=wait_time):
            return False
    return not cancel_event.is_set()
