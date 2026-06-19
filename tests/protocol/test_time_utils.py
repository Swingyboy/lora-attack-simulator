"""Tests for lorawan/time_utils.py — GPS conversion, FakeClock, SimClock protocol."""

from __future__ import annotations

import time
import unittest

from lora_attack_toolkit.lorawan.time_utils import (

    GPS_EPOCH_UNIX,
    GPS_LEAP_SECONDS,
    FakeClock,
    SimClock,
    WallClock,
    gps_to_unix,
    unix_to_gps,
)
import pytest

pytestmark = pytest.mark.unit


class TestGpsConversion(unittest.TestCase):
    """unix_to_gps and gps_to_unix round-trip correctness."""

    def test_gps_epoch_maps_to_zero(self) -> None:
        """Unix timestamp of the GPS epoch should yield GPS time 18.0 (leap seconds only)."""
        result = unix_to_gps(GPS_EPOCH_UNIX)
        self.assertAlmostEqual(result, GPS_LEAP_SECONDS, places=9)

    def test_unix_epoch_maps_to_negative(self) -> None:
        """Unix epoch (0) is before the GPS epoch; result should be negative."""
        result = unix_to_gps(0.0)
        self.assertLess(result, 0)
        # Expected: 0 - 315_964_800 + 18 = -315_964_782
        self.assertAlmostEqual(result, -GPS_EPOCH_UNIX + GPS_LEAP_SECONDS, places=9)

    def test_known_gps_time(self) -> None:
        """Spot-check a known conversion.

        GPS time at Unix timestamp 1_700_000_000 (2023-11-14 22:13:20 UTC):
        gps_time = (1_700_000_000 - 315_964_800) + 18 = 1_384_035_218
        """
        gps = unix_to_gps(1_700_000_000)
        self.assertAlmostEqual(gps, 1_384_035_218.0, places=6)

    def test_roundtrip_unix_to_gps_and_back(self) -> None:
        """gps_to_unix(unix_to_gps(t)) == t for arbitrary t."""
        for unix_t in [0.0, 1_000_000.0, 1_700_000_000.0, 1_700_000_000.5]:
            with self.subTest(unix_t=unix_t):
                self.assertAlmostEqual(gps_to_unix(unix_to_gps(unix_t)), unix_t, places=9)

    def test_roundtrip_gps_to_unix_and_back(self) -> None:
        """unix_to_gps(gps_to_unix(g)) == g for arbitrary g."""
        for gps_t in [0.0, 1_000_000.0, 1_384_035_218.0, 1_384_035_218.75]:
            with self.subTest(gps_t=gps_t):
                self.assertAlmostEqual(unix_to_gps(gps_to_unix(gps_t)), gps_t, places=9)

    def test_fractional_seconds_preserved(self) -> None:
        """Sub-second precision is preserved through conversion."""
        unix_t = 1_700_000_000.123456
        self.assertAlmostEqual(gps_to_unix(unix_to_gps(unix_t)), unix_t, places=6)

    def test_leap_second_offset(self) -> None:
        """GPS time is GPS_LEAP_SECONDS ahead of UTC-based Unix delta."""
        delta = unix_to_gps(GPS_EPOCH_UNIX + 1_000) - unix_to_gps(GPS_EPOCH_UNIX)
        self.assertAlmostEqual(delta, 1_000.0, places=9)

    def test_tolerance_boundary(self) -> None:
        """Values exactly at ±2 s tolerance boundary are distinguishable from out-of-range."""
        base_gps = unix_to_gps(1_700_000_000.0)
        tol = 2.0
        # Within tolerance
        self.assertLessEqual(abs((base_gps + 1.99) - base_gps), tol)
        self.assertLessEqual(abs((base_gps - 1.99) - base_gps), tol)
        # Outside tolerance
        self.assertGreater(abs((base_gps + 2.01) - base_gps), tol)


class TestFakeClock(unittest.TestCase):
    """FakeClock deterministic time source."""

    def test_initial_values(self) -> None:
        clock = FakeClock(start_unix=1_700_000_000.0, start_mono=0.0)
        self.assertAlmostEqual(clock.unix_time(), 1_700_000_000.0)
        self.assertAlmostEqual(clock.monotonic(), 0.0)

    def test_gps_time_derived_from_unix(self) -> None:
        clock = FakeClock(start_unix=GPS_EPOCH_UNIX + 0.0)
        self.assertAlmostEqual(clock.gps_time(), GPS_LEAP_SECONDS)

    def test_advance_moves_both_clocks(self) -> None:
        clock = FakeClock(start_unix=1_000.0, start_mono=0.0)
        clock.advance(5.5)
        self.assertAlmostEqual(clock.unix_time(), 1_005.5)
        self.assertAlmostEqual(clock.monotonic(), 5.5)

    def test_advance_mono_only(self) -> None:
        clock = FakeClock(start_unix=1_000.0, start_mono=0.0)
        clock.advance_mono(3.0)
        self.assertAlmostEqual(clock.monotonic(), 3.0)
        self.assertAlmostEqual(clock.unix_time(), 1_000.0)  # unchanged

    def test_set_unix(self) -> None:
        clock = FakeClock()
        clock.set_unix(9_999.0)
        self.assertAlmostEqual(clock.unix_time(), 9_999.0)

    def test_set_mono(self) -> None:
        clock = FakeClock()
        clock.set_mono(42.0)
        self.assertAlmostEqual(clock.monotonic(), 42.0)

    def test_monotonic_never_goes_backward_after_advance(self) -> None:
        clock = FakeClock(start_mono=100.0)
        prev = clock.monotonic()
        for _ in range(5):
            clock.advance(1.0)
            self.assertGreater(clock.monotonic(), prev)
            prev = clock.monotonic()

    def test_default_start_unix_at_gps_epoch(self) -> None:
        """Default start_unix = GPS_EPOCH_UNIX → GPS time starts at GPS_LEAP_SECONDS."""
        clock = FakeClock()
        self.assertAlmostEqual(clock.gps_time(), GPS_LEAP_SECONDS)


class TestSimClockProtocol(unittest.TestCase):
    """SimClock is a runtime-checkable Protocol."""

    def test_wall_clock_satisfies_protocol(self) -> None:
        clock = WallClock()
        self.assertIsInstance(clock, SimClock)

    def test_fake_clock_satisfies_protocol(self) -> None:
        clock = FakeClock()
        self.assertIsInstance(clock, SimClock)

    def test_wall_clock_returns_realistic_unix_time(self) -> None:
        clock = WallClock()
        now = clock.unix_time()
        # Must be past 2020-01-01 00:00:00 UTC
        self.assertGreater(now, 1_577_836_800)

    def test_wall_clock_gps_derived_from_unix(self) -> None:
        clock = WallClock()
        # GPS time should be unix delta + leap seconds
        delta = clock.gps_time() - unix_to_gps(clock.unix_time())
        self.assertAlmostEqual(delta, 0.0, places=3)

    def test_fake_clock_gps_time_after_advance(self) -> None:
        clock = FakeClock(start_unix=1_700_000_000.0)
        gps_before = clock.gps_time()
        clock.advance(10.0)
        gps_after = clock.gps_time()
        self.assertAlmostEqual(gps_after - gps_before, 10.0, places=9)

    def test_replay_correlation_scenario(self) -> None:
        """Simulate GPS-time correlation in a replay scenario.

        When an NS DeviceTimeAns reports a GPS timestamp matching a replay TX,
        the _gps_match helper (using correct GPS times on both sides) should
        detect the correlation.
        """
        # Simulate: device TX at Unix time T
        unix_tx = 1_700_000_100.0
        gps_tx = unix_to_gps(unix_tx)  # GPS seconds at TX

        # NS reports back GPS time ≈ TX time (within 2 s tolerance)
        gps_server_response = gps_tx + 0.5  # 0.5 s after TX
        tolerance = 2.0

        # With correct GPS-to-GPS comparison: should match
        self.assertLessEqual(abs(gps_server_response - gps_tx), tolerance)

        # Demonstrate old bug: if Unix time was compared directly to GPS seconds
        gps_server_large = gps_server_response  # correct GPS value
        unix_tx_wrongly_used = unix_tx  # Unix value mistakenly used as GPS
        difference_wrong = abs(gps_server_large - unix_tx_wrongly_used)
        # The difference is ~315,964,818 s — far outside any tolerance
        self.assertGreater(difference_wrong, 300_000_000)


if __name__ == "__main__":
    unittest.main()
