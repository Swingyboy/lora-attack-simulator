"""Region-specific LoRaWAN channel plan abstraction.

Supports:
  - EU868 (fully implemented, including Duty Cycle enforcement)
  - Other regions: pass-through stub (no channel rotation, no CFList)

Architecture
------------
RegionChannelPlan
  ├── EU868ChannelPlan   (channel rotation, CFList, Duty Cycle enforcement)
  └── PassthroughChannelPlan   (default for unknown regions)

Duty Cycle
----------
EU868 enforces ETSI sub-band duty cycle limits.  Regional constants are fixed
in code and not user-configurable.  Users may only enable/disable enforcement:

    plan = get_channel_plan("EU868", duty_cycle_enforcement=True)
    ch   = plan.select_join_channel(attempt_index=0, now=time.time())
    plan.record_transmission(ch, airtime_sec=0.05, now=time.time())

Usage
-----
plan = get_channel_plan("EU868", default_frequency_hz=868100000)
ch   = plan.select_join_channel(attempt_index=0)   # 868.1 MHz
plan.apply_cflist(cflist_bytes)
ch   = plan.select_uplink_channel(uplink_index=0)
"""

from __future__ import annotations

import math
import re
import time as _time
from dataclasses import dataclass, field
from logging import Logger


@dataclass
class Channel:
    """A single LoRaWAN channel descriptor."""

    frequency_hz: int
    data_rate: str = "SF7BW125"

    def __repr__(self) -> str:  # pragma: no cover
        return f"Channel({self.frequency_hz / 1_000_000:.3f} MHz, {self.data_rate})"


# ─── Airtime Calculator ───────────────────────────────────────────────────────


class AirtimeCalculator:
    """LoRa on-air time calculator (Semtech AN1200.13 formula).

    Independent from attack logic and reusable by all regions.
    """

    @staticmethod
    def calculate(data_rate: str, payload_size_bytes: int) -> float:
        """Calculate LoRa packet airtime in seconds.

        Args:
            data_rate: Data rate string (e.g., "SF7BW125").
            payload_size_bytes: Full PHYPayload size in bytes.

        Returns:
            Estimated on-air time in seconds.
        """
        m = re.match(r"SF(\d+)BW(\d+)", data_rate.upper())
        if not m:
            return 0.1  # conservative fallback for unknown formats

        sf = int(m.group(1))
        bw_hz = int(m.group(2)) * 1_000  # kHz → Hz

        t_sym = (2 ** sf) / bw_hz  # symbol duration (s)
        t_preamble = (8 + 4.25) * t_sym  # 8-symbol preamble + 4.25 sync symbols

        # Low Data Rate Optimization required when symbol time >= 16 ms
        de = 1 if t_sym >= 0.016 else 0
        # Explicit header, CR 4/5
        cr = 1
        ih = 0
        pl = payload_size_bytes

        num = max(8 * pl - 4 * sf + 28 + 16 - 20 * ih, 0)
        den = 4 * (sf - 2 * de)
        payload_symb_nb = 8 + math.ceil(num / den) * (cr + 4)

        return t_preamble + payload_symb_nb * t_sym


# ─── Region base class ────────────────────────────────────────────────────────


class RegionChannelPlan:
    """Base class for region-specific channel plans."""

    region: str = "unknown"

    # --- Duty Cycle ---

    def supports_duty_cycle(self) -> bool:
        """Return True if this region implements Duty Cycle enforcement."""
        return False

    def can_transmit(self, channel: Channel, now: float) -> bool:
        """Return True if the channel is available for transmission at *now*."""
        return True

    def record_transmission(self, channel: Channel, airtime_sec: float, now: float) -> None:
        """Record a completed transmission for Duty Cycle bookkeeping."""
        pass  # no-op for regions without Duty Cycle

    def next_available_time(self, channel: Channel, now: float) -> float:
        """Return the earliest time (epoch seconds) when *channel* may be used."""
        return now

    # --- Join channels ---

    def get_join_channels(self) -> list[Channel]:
        """Return the default join channels for this region."""
        raise NotImplementedError

    def select_join_channel(self, attempt_index: int, now: float | None = None) -> Channel:
        """Return the channel for the given JoinRequest attempt (0-based).

        When *now* is provided and the region supports Duty Cycle enforcement,
        the region may skip unavailable channels and wait if all are busy.
        """
        channels = self.get_join_channels()
        return channels[attempt_index % len(channels)]

    # --- Uplink channels ---

    def get_uplink_channels(self) -> list[Channel]:
        """Return the current active uplink channels."""
        raise NotImplementedError

    def select_uplink_channel(self, uplink_index: int, now: float | None = None) -> Channel:
        """Return the channel for the given uplink (0-based).

        When *now* is provided and the region supports Duty Cycle enforcement,
        the region may skip unavailable channels and wait if all are busy.
        """
        channels = self.get_uplink_channels()
        return channels[uplink_index % len(channels)]

    # --- CFList ---

    def apply_cflist(self, cflist: bytes | None) -> None:
        """Parse and apply a CFList from a JoinAccept payload, if present."""
        pass  # Default: no-op


# ─── EU868 ────────────────────────────────────────────────────────────────────

_EU868_JOIN_FREQUENCIES_HZ: list[int] = [
    868_100_000,
    868_300_000,
    868_500_000,
]

_EU868_DEFAULT_UPLINK_FREQUENCIES_HZ: list[int] = [
    868_100_000,
    868_300_000,
    868_500_000,
]

# ETSI EN 300 220 sub-band duty cycle limits — fixed by regional specification,
# not user-configurable.  (low_hz, high_hz_inclusive, duty_cycle_fraction)
_EU868_DUTY_CYCLES: list[tuple[int, int, float]] = [
    (868_000_000, 868_600_000, 0.01),   # g1: 1 %  (default 3 channels)
    (868_700_000, 869_200_000, 0.001),  # g2: 0.1 %
    (869_400_000, 869_650_000, 0.10),   # g3: 10 %
]
_EU868_DEFAULT_DUTY_CYCLE: float = 0.01  # 1 % for channels outside defined sub-bands

# Fixed PHYPayload sizes used for Duty Cycle reservation at channel-selection time.
# JoinRequest is always exactly 23 bytes (MHDR+JoinEUI+DevEUI+DevNonce+MIC).
_EU868_JOIN_REQUEST_SIZE: int = 23
# Minimum LoRaWAN uplink (MHDR+FHDR+MIC, empty payload, no FPort).
_EU868_MIN_UPLINK_SIZE: int = 12


class EU868ChannelPlan(RegionChannelPlan):
    """EU868 channel plan (LoRaWAN Regional Parameters v1.0.3 §2.2).

    Join channels: 868.1 / 868.3 / 868.5 MHz
    Default uplink channels: same as join channels
    CFList type 0: up to 5 additional 100-Hz-resolution frequencies

    Duty Cycle
    ----------
    EU868 enforces per-channel Duty Cycle based on ETSI sub-band limits.
    Duty Cycle percentages are fixed in code and not user-configurable.
    Pass ``duty_cycle_enforcement=False`` to disable for testing/debugging.
    """

    region: str = "EU868"

    def __init__(
        self,
        data_rate: str = "SF7BW125",
        duty_cycle_enforcement: bool = True,
        logger: Logger | None = None,
    ) -> None:
        self._data_rate = data_rate
        self._duty_cycle_enforcement = duty_cycle_enforcement
        self._logger = logger
        self._base_uplink_frequencies_hz: list[int] = list(_EU868_DEFAULT_UPLINK_FREQUENCIES_HZ)
        self._cflist_uplink_frequencies_hz: list[int] = []
        # Per-channel availability: freq_hz → earliest next-TX epoch timestamp
        self._channel_available_after: dict[int, float] = {}

        if logger:
            if duty_cycle_enforcement:
                logger.info("EU868 Duty Cycle enabled")
            else:
                logger.info("EU868 Duty Cycle enforcement disabled")

    # --- Duty Cycle interface ---

    def supports_duty_cycle(self) -> bool:
        return True

    def _get_duty_cycle(self, freq_hz: int) -> float:
        """Return the ETSI duty cycle fraction for this frequency."""
        for low, high, dc in _EU868_DUTY_CYCLES:
            if low <= freq_hz <= high:
                return dc
        return _EU868_DEFAULT_DUTY_CYCLE

    def can_transmit(self, channel: Channel, now: float) -> bool:
        """Return True if the channel is available at *now*."""
        if not self._duty_cycle_enforcement:
            return True
        available_after = self._channel_available_after.get(channel.frequency_hz, 0.0)
        return now >= available_after

    def record_transmission(self, channel: Channel, airtime_sec: float, now: float) -> None:
        """Record a transmission and update the channel's next-available time.

        The time-off period is computed from the fixed regional Duty Cycle:
            time_off = airtime * (1 / duty_cycle - 1)
        so the channel becomes available again at ``now + airtime / duty_cycle``.
        """
        if not self._duty_cycle_enforcement:
            return
        dc = self._get_duty_cycle(channel.frequency_hz)
        self._channel_available_after[channel.frequency_hz] = now + airtime_sec / dc

    def next_available_time(self, channel: Channel, now: float) -> float:
        """Return the earliest epoch time when *channel* may be used again."""
        return max(self._channel_available_after.get(channel.frequency_hz, 0.0), now)

    # --- Channel selection ---

    def get_join_channels(self) -> list[Channel]:
        return [Channel(f, self._data_rate) for f in _EU868_JOIN_FREQUENCIES_HZ]

    def get_uplink_channels(self) -> list[Channel]:
        combined = self._base_uplink_frequencies_hz + self._cflist_uplink_frequencies_hz
        return [Channel(f, self._data_rate) for f in combined]

    def select_join_channel(self, attempt_index: int, now: float | None = None) -> Channel:
        """Return the channel for the given JoinRequest attempt.

        When *now* is provided and Duty Cycle enforcement is active the method:
        1. Prefers the natural round-robin channel if available.
        2. Falls back to any other available channel.
        3. Waits (sleeps) until the earliest channel becomes available if all
           are currently busy, then returns that channel.

        The selected channel is reserved via an automatic ``record_transmission``
        call using the fixed EU868 JoinRequest payload size.
        """
        channels = self.get_join_channels()
        if now is None or not self._duty_cycle_enforcement:
            return channels[attempt_index % len(channels)]
        return self._select_with_duty_cycle(
            channels, attempt_index, now, payload_size=_EU868_JOIN_REQUEST_SIZE
        )

    def select_uplink_channel(self, uplink_index: int, now: float | None = None) -> Channel:
        """Return the channel for the given uplink.

        Behaviour with Duty Cycle enforcement is identical to
        ``select_join_channel``; see its docstring for details.

        The reservation uses ``_EU868_MIN_UPLINK_SIZE`` as a conservative
        airtime estimate.  Callers with the actual frame size may call
        ``record_transmission`` afterwards to update the reservation.
        """
        channels = self.get_uplink_channels()
        if now is None or not self._duty_cycle_enforcement:
            return channels[uplink_index % len(channels)]
        return self._select_with_duty_cycle(
            channels, uplink_index, now, payload_size=_EU868_MIN_UPLINK_SIZE
        )

    def _select_with_duty_cycle(
        self,
        channels: list[Channel],
        index: int,
        now: float,
        payload_size: int,
    ) -> Channel:
        """Internal: select a channel honouring Duty Cycle, then reserve it."""
        preferred = channels[index % len(channels)]

        if self.can_transmit(preferred, now):
            self._log_selected(preferred)
            self._reserve(preferred, payload_size, now)
            return preferred

        self._log_unavailable(preferred)

        # Try the remaining channels in rotation order
        for ch in channels:
            if ch.frequency_hz == preferred.frequency_hz:
                continue
            if self.can_transmit(ch, now):
                self._log_selected(ch)
                self._reserve(ch, payload_size, now)
                return ch
            self._log_unavailable(ch)

        # All channels busy: wait for the one that frees up soonest
        earliest = min(
            channels,
            key=lambda c: self._channel_available_after.get(c.frequency_hz, 0.0),
        )
        wait_sec = self._channel_available_after.get(earliest.frequency_hz, 0.0) - now
        if wait_sec > 0:
            if self._logger:
                self._logger.info("Waiting %.1fs for next available transmission", wait_sec)
            _time.sleep(wait_sec)

        actual_now = _time.time()
        self._log_selected(earliest)
        self._reserve(earliest, payload_size, actual_now)
        return earliest

    def _reserve(self, channel: Channel, payload_size: int, now: float) -> None:
        """Record an estimated transmission reservation for Duty Cycle tracking."""
        airtime = AirtimeCalculator.calculate(channel.data_rate, payload_size)
        self.record_transmission(channel, airtime, now)

    def _log_selected(self, channel: Channel) -> None:
        if self._logger:
            self._logger.debug("Selected channel %d", channel.frequency_hz)

    def _log_unavailable(self, channel: Channel) -> None:
        if self._logger:
            self._logger.debug(
                "Channel %d unavailable due to Duty Cycle", channel.frequency_hz
            )

    # --- CFList ---

    def apply_cflist(self, cflist: bytes | None) -> None:
        """Parse EU868 CFList type 0 and replace CFList-derived channels.

        CFList layout (16 bytes):
          bytes  0-2:  freq[0]  (3 bytes, little-endian, unit = 100 Hz)
          bytes  3-5:  freq[1]
          bytes  6-8:  freq[2]
          bytes  9-11: freq[3]
          bytes 12-14: freq[4]
          byte  15:    CFListType (0 = frequencies)

        Valid Type 0 CFList channels *replace* any previously learned
        CFList channels — they are never accumulated across calls.
        Base channels (868.1 / 868.3 / 868.5 MHz) are always preserved.
        """
        if not cflist or len(cflist) != 16:
            return
        cflist_type = cflist[15]
        if cflist_type != 0:
            return

        base = set(self._base_uplink_frequencies_hz)
        seen: set[int] = set()
        new_cflist: list[int] = []

        for i in range(5):
            raw = cflist[i * 3 : i * 3 + 3]
            value = int.from_bytes(raw, "little")
            if value == 0:
                continue  # unused slot
            freq_hz = value * 100
            if freq_hz in base or freq_hz in seen:
                continue
            new_cflist.append(freq_hz)
            seen.add(freq_hz)

        # Replace (not append) previous CFList-derived channels.
        self._cflist_uplink_frequencies_hz = new_cflist


# ─── Passthrough (unknown region) ────────────────────────────────────────────


class PassthroughChannelPlan(RegionChannelPlan):
    """No-op channel plan for unsupported regions.

    Always returns a single channel with the frequency provided at construction.
    This preserves existing behavior for regions not yet explicitly supported.
    """

    region: str = "unknown"

    def __init__(self, region: str, frequency_hz: int, data_rate: str = "SF7BW125") -> None:
        self.region = region
        self._channel = Channel(frequency_hz, data_rate)

    def get_join_channels(self) -> list[Channel]:
        return [self._channel]

    def get_uplink_channels(self) -> list[Channel]:
        return [self._channel]


# ─── Factory ──────────────────────────────────────────────────────────────────


def get_channel_plan(
    region: str,
    default_frequency_hz: int = 868_100_000,
    data_rate: str = "SF7BW125",
    duty_cycle_enforcement: bool = True,
    logger: Logger | None = None,
) -> RegionChannelPlan:
    """Return the appropriate channel plan for the given region.

    Args:
        region: LoRaWAN region string (e.g. "EU868", "US915").
        default_frequency_hz: Fallback frequency for unsupported regions.
        data_rate: LoRa data-rate string (e.g. "SF7BW125").
        duty_cycle_enforcement: Enable/disable EU868 Duty Cycle enforcement.
            Duty Cycle percentages are always fixed; this flag only controls
            whether enforcement is active.  Default is True.
        logger: Optional logger for Duty Cycle decision messages.

    Returns:
        A concrete RegionChannelPlan instance.
    """
    if region.upper() == "EU868":
        return EU868ChannelPlan(
            data_rate=data_rate,
            duty_cycle_enforcement=duty_cycle_enforcement,
            logger=logger,
        )
    return PassthroughChannelPlan(
        region=region,
        frequency_hz=default_frequency_hz,
        data_rate=data_rate,
    )
