"""LoRaWAN radio state — the single source of truth for device radio behaviour.

Owns:
* Regional base channels and frequency constraints (RegionProfile).
* CFList-derived channels (replaced on each valid JoinAccept, never accumulated).
* Current data-rate and TX-power state.
* Per-channel duty-cycle availability state.
* Join-channel and uplink-channel selection (with optional duty-cycle enforcement).

Typical usage::

    radio = Radio(EU868RegionProfile(), duty_cycle_enforcement=True, logger=logger)
    radio.apply_cflist(cflist_bytes)

    # In OTAA join loop:
    tx = radio.select_join_channel(attempt_index, now=time.time())

    # In uplink loop:
    tx = radio.select_uplink_channel(uplink_index, now=time.time())
    gateway.forward_uplink(frame, RadioMetadata(tx.frequency_hz, tx.data_rate, ...))
    radio.record_transmission(tx.frequency_hz, airtime_sec, now)
"""

from __future__ import annotations

import logging
import time as _time
from abc import ABC
from dataclasses import dataclass
from logging import Logger
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lora_attack_toolkit.lorawan.protocol.mac_commands import MACCommand


# ─── Region profiles ──────────────────────────────────────────────────────────


class RegionProfile(ABC):
    """Static constants describing a LoRaWAN regional radio profile.

    All attributes are class-level constants; subclasses define them as class
    variables so instances are cheap to share.
    """

    #: Short region identifier, e.g. ``"EU868"``.
    REGION_NAME: str

    #: Mandatory base uplink channel frequencies (Hz) — never removed by CFList.
    BASE_UPLINK_CHANNELS_HZ: list[int]

    #: Lowest valid uplink frequency for this region (Hz).
    FREQ_MIN_HZ: int

    #: Highest valid uplink frequency for this region (Hz).
    FREQ_MAX_HZ: int

    #: Default LoRa data-rate string, e.g. ``"SF7BW125"``.
    DEFAULT_DATA_RATE: str

    #: Default TX power (dBm).
    DEFAULT_TX_POWER: int

    #: ETSI sub-band duty-cycle limits: ``[(low_hz, high_hz_inclusive, fraction), ...]``.
    #: Empty list means no duty-cycle enforcement for this region.
    DUTY_CYCLES: list[tuple[int, int, float]] = []

    #: Fallback duty-cycle fraction for frequencies outside defined sub-bands.
    DEFAULT_DUTY_CYCLE: float = 0.01

    #: Fixed JoinRequest PHYPayload size (bytes) used for conservative DC reservation.
    JOIN_REQUEST_SIZE_BYTES: int = 23

    #: Minimum uplink PHYPayload size (bytes) used for conservative DC reservation.
    MIN_UPLINK_SIZE_BYTES: int = 12


class EU868RegionProfile(RegionProfile):
    """EU868 regional constants (LoRaWAN Regional Parameters v1.0.3 §2.2).

    Base uplink / join channels (always preserved):
        868.1 / 868.3 / 868.5 MHz

    CFList allowed range:
        863 – 870 MHz  (ETSI EN 300 220-2 sub-bands g, g1, g2, g3)

    Duty-cycle limits (ETSI EN 300 220):
        g1 — 868.0–868.6 MHz:  1 %
        g2 — 868.7–869.2 MHz:  0.1 %
        g3 — 869.4–869.65 MHz: 10 %
    """

    REGION_NAME = "EU868"
    BASE_UPLINK_CHANNELS_HZ: list[int] = [868_100_000, 868_300_000, 868_500_000]
    FREQ_MIN_HZ: int = 863_000_000
    FREQ_MAX_HZ: int = 870_000_000
    DEFAULT_DATA_RATE: str = "SF7BW125"
    DEFAULT_TX_POWER: int = 14
    DUTY_CYCLES: list[tuple[int, int, float]] = [
        (868_000_000, 868_600_000, 0.01),   # g1: 1 %
        (868_700_000, 869_200_000, 0.001),  # g2: 0.1 %
        (869_400_000, 869_650_000, 0.10),   # g3: 10 %
    ]
    DEFAULT_DUTY_CYCLE: float = 0.01
    JOIN_REQUEST_SIZE_BYTES: int = 23
    MIN_UPLINK_SIZE_BYTES: int = 12


# ─── TX parameter descriptor ─────────────────────────────────────────────────


@dataclass(frozen=True)
class RadioTxParams:
    """Parameters for a single uplink or join-request transmission."""

    frequency_hz: int
    data_rate: str
    tx_power: int


# ─── Radio ────────────────────────────────────────────────────────────────────


class Radio:
    """Simulated device radio — single source of truth for radio state.

    Parameters
    ----------
    region:
        Regional profile supplying base channels, frequency range,
        duty-cycle limits, and default DR / TX-power.
    duty_cycle_enforcement:
        When ``True`` (default) the radio enforces ETSI sub-band duty-cycle
        limits; unavailable channels are skipped or waited for.
        Set to ``False`` for testing or to simulate a non-compliant device.
    logger:
        Optional logger for radio state-change events.
    """

    def __init__(
        self,
        region: RegionProfile,
        duty_cycle_enforcement: bool = True,
        logger: Logger | None = None,
    ) -> None:
        self._region = region
        self._duty_cycle_enforcement = duty_cycle_enforcement
        self._logger = logger or logging.getLogger(__name__)

        self._base_uplink_channels_hz: list[int] = list(region.BASE_UPLINK_CHANNELS_HZ)
        self._cflist_channels_hz: list[int] = []
        self._data_rate: str = region.DEFAULT_DATA_RATE
        self._tx_power: int = region.DEFAULT_TX_POWER

        # Duty-cycle availability: freq_hz → earliest next-TX epoch time
        self._channel_available_after: dict[int, float] = {}

        # Internal round-robin counter (used by get_next_uplink_channel)
        self._uplink_index: int = 0

        self._logger.info(
            "Radio initialised region=%s duty_cycle=%s",
            region.REGION_NAME,
            duty_cycle_enforcement,
        )

    # ------------------------------------------------------------------
    # Read-only properties
    # ------------------------------------------------------------------

    @property
    def region_name(self) -> str:
        return self._region.REGION_NAME

    def supports_duty_cycle(self) -> bool:
        """Return ``True`` if duty-cycle enforcement is active for this region."""
        return self._duty_cycle_enforcement and bool(self._region.DUTY_CYCLES)

    # ------------------------------------------------------------------
    # CFList
    # ------------------------------------------------------------------

    def apply_cflist(self, cflist: bytes | None) -> None:
        """Parse and apply a JoinAccept CFList (Type 0 — frequency list).

        Valid parsed frequencies *replace* the previous CFList-derived
        channels.  Base channels are never modified.

        CFList layout (16 bytes):
          bytes  0-2:   freq[0]  (3 bytes, little-endian, unit = 100 Hz)
          …
          byte   15:    CFListType (0 = frequency list)

        Ignored without mutating radio state:
          * ``None``
          * length ≠ 16
          * CFListType ≠ 0
        """
        if cflist is None:
            self._logger.debug("radio_cflist_ignored reason=none")
            return

        if len(cflist) != 16:
            self._logger.debug(
                "radio_cflist_ignored reason=wrong_length length=%d", len(cflist)
            )
            return

        cflist_type = cflist[15]
        if cflist_type != 0:
            self._logger.debug(
                "radio_cflist_ignored reason=unsupported_type cflist_type=%d", cflist_type
            )
            return

        base = set(self._base_uplink_channels_hz)
        seen: set[int] = set()
        new_cflist: list[int] = []

        for i in range(5):
            raw = cflist[i * 3 : i * 3 + 3]
            value = int.from_bytes(raw, "little")
            if value == 0:
                continue
            freq_hz = value * 100
            if not (self._region.FREQ_MIN_HZ <= freq_hz <= self._region.FREQ_MAX_HZ):
                self._logger.debug(
                    "radio_cflist_freq_ignored freq_hz=%d reason=out_of_range", freq_hz
                )
                continue
            if freq_hz in base or freq_hz in seen:
                continue
            new_cflist.append(freq_hz)
            seen.add(freq_hz)

        self._cflist_channels_hz = new_cflist
        self._logger.info(
            "radio_cflist_applied region=%s base=%s cflist=%s active=%s",
            self._region.REGION_NAME,
            self._base_uplink_channels_hz,
            self._cflist_channels_hz,
            self.get_active_uplink_channels(),
        )

    # ------------------------------------------------------------------
    # Channel lists
    # ------------------------------------------------------------------

    def get_active_uplink_channels(self) -> list[int]:
        """Return current active uplink channel frequencies (Hz).

        Always includes base channels; CFList-derived channels follow when set.
        """
        return self._base_uplink_channels_hz + self._cflist_channels_hz

    # ------------------------------------------------------------------
    # Channel selection — duty-cycle aware
    # ------------------------------------------------------------------

    def select_join_channel(
        self, attempt_index: int, now: float | None = None
    ) -> RadioTxParams:
        """Return TX parameters for the given JoinRequest attempt (0-based).

        When *now* is provided and duty-cycle enforcement is active the method:

        1. Prefers the natural round-robin channel if available.
        2. Falls back to any other available channel.
        3. Waits (sleeps) until the earliest channel becomes free if all are
           busy, then returns that channel.

        .. note::
            The selected channel is reserved with a conservative
            ``JOIN_REQUEST_SIZE_BYTES`` airtime estimate.  Callers with the
            actual frame size may call :meth:`record_transmission` afterwards.
        """
        channels_hz = self._base_uplink_channels_hz  # join channels = base channels
        if now is None or not self.supports_duty_cycle():
            freq = channels_hz[attempt_index % len(channels_hz)]
            return RadioTxParams(freq, self._data_rate, self._tx_power)
        return self._select_with_duty_cycle(
            channels_hz, attempt_index, now, self._region.JOIN_REQUEST_SIZE_BYTES
        )

    def select_uplink_channel(
        self, uplink_index: int, now: float | None = None
    ) -> RadioTxParams:
        """Return TX parameters for the given uplink (0-based).

        Duty-cycle behaviour is identical to :meth:`select_join_channel`.
        The conservative reservation uses ``MIN_UPLINK_SIZE_BYTES``.
        """
        channels_hz = self.get_active_uplink_channels()
        if now is None or not self.supports_duty_cycle():
            freq = channels_hz[uplink_index % len(channels_hz)]
            return RadioTxParams(freq, self._data_rate, self._tx_power)
        return self._select_with_duty_cycle(
            channels_hz, uplink_index, now, self._region.MIN_UPLINK_SIZE_BYTES
        )

    def get_next_uplink_channel(self) -> int:
        """Return the next uplink channel frequency (Hz) via round-robin.

        Uses an internal counter; no duty-cycle check.
        Useful for simple tests and scenarios where duty-cycle is not needed.
        """
        channels = self.get_active_uplink_channels()
        freq = channels[self._uplink_index % len(channels)]
        self._uplink_index += 1
        return freq

    # ------------------------------------------------------------------
    # Duty-cycle state
    # ------------------------------------------------------------------

    def can_transmit(self, freq_hz: int, now: float) -> bool:
        """Return ``True`` if *freq_hz* is available for transmission at *now*."""
        if not self._duty_cycle_enforcement:
            return True
        return now >= self._channel_available_after.get(freq_hz, 0.0)

    def record_transmission(
        self, freq_hz: int, airtime_sec: float, now: float
    ) -> None:
        """Record a completed transmission and update the channel's duty-cycle state.

        ``time_off = airtime * (1 / duty_cycle - 1)``
        so the channel becomes available again at ``now + airtime / duty_cycle``.
        """
        if not self._duty_cycle_enforcement:
            return
        dc = self._get_duty_cycle(freq_hz)
        self._channel_available_after[freq_hz] = now + airtime_sec / dc

    def next_available_time(self, freq_hz: int, now: float) -> float:
        """Return the earliest epoch time when *freq_hz* may be used again."""
        return max(self._channel_available_after.get(freq_hz, 0.0), now)

    # ------------------------------------------------------------------
    # Data rate / TX power
    # ------------------------------------------------------------------

    def get_current_data_rate(self) -> str:
        """Return the current data-rate string (e.g. ``"SF7BW125"``)."""
        return self._data_rate

    def get_current_tx_power(self) -> int:
        """Return the current TX power in dBm."""
        return self._tx_power

    # ------------------------------------------------------------------
    # Future extension points
    # ------------------------------------------------------------------

    def apply_mac_command(self, command: "MACCommand") -> None:
        """Apply a radio-affecting MAC command (future: LinkADRReq, NewChannelReq…)."""

    def apply_adr_settings(
        self,
        data_rate: int | None = None,
        tx_power: int | None = None,
    ) -> None:
        """Apply ADR-driven data-rate and TX-power changes (future)."""

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_duty_cycle(self, freq_hz: int) -> float:
        """Return the duty-cycle fraction for *freq_hz*."""
        for low, high, dc in self._region.DUTY_CYCLES:
            if low <= freq_hz <= high:
                return dc
        return self._region.DEFAULT_DUTY_CYCLE

    def _select_with_duty_cycle(
        self,
        channels_hz: list[int],
        index: int,
        now: float,
        payload_size: int,
    ) -> RadioTxParams:
        """Select a channel honouring duty-cycle, then reserve it."""
        preferred = channels_hz[index % len(channels_hz)]

        if self.can_transmit(preferred, now):
            self._log_selected(preferred)
            self._reserve(preferred, payload_size, now)
            return RadioTxParams(preferred, self._data_rate, self._tx_power)

        self._log_unavailable(preferred)

        for freq in channels_hz:
            if freq == preferred:
                continue
            if self.can_transmit(freq, now):
                self._log_selected(freq)
                self._reserve(freq, payload_size, now)
                return RadioTxParams(freq, self._data_rate, self._tx_power)
            self._log_unavailable(freq)

        # All busy — wait for the earliest
        earliest = min(
            channels_hz,
            key=lambda f: self._channel_available_after.get(f, 0.0),
        )
        wait_sec = self._channel_available_after.get(earliest, 0.0) - now
        if wait_sec > 0:
            self._logger.info("Waiting %.1fs for next available channel", wait_sec)
            _time.sleep(wait_sec)

        actual_now = _time.time()
        self._log_selected(earliest)
        self._reserve(earliest, payload_size, actual_now)
        return RadioTxParams(earliest, self._data_rate, self._tx_power)

    def _reserve(self, freq_hz: int, payload_size: int, now: float) -> None:
        """Record a conservative transmission reservation for duty-cycle tracking."""
        from lora_attack_toolkit.lorawan.channel_plan import AirtimeCalculator

        airtime = AirtimeCalculator.calculate(self._data_rate, payload_size)
        self.record_transmission(freq_hz, airtime, now)

    def _log_selected(self, freq_hz: int) -> None:
        self._logger.debug("radio_channel_selected freq_hz=%d", freq_hz)

    def _log_unavailable(self, freq_hz: int) -> None:
        self._logger.debug("radio_channel_unavailable freq_hz=%d reason=duty_cycle", freq_hz)
