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
    tx = radio.select_join_channel(attempt_index, now=time.monotonic())

    # In uplink loop:
    tx = radio.select_uplink_channel(uplink_index, now=time.monotonic())
    gateway.forward_uplink(frame, RadioMetadata(tx.frequency_hz, tx.data_rate, ...))
    radio.record_transmission(tx.frequency_hz, airtime_sec, now)
"""

from __future__ import annotations

import logging
import math
import re
import time as _time
from abc import ABC
from dataclasses import dataclass
from logging import Logger
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# ── EU868 index-to-value tables (LoRaWAN 1.0.3 Regional Parameters §2.2) ─────

#: EU868 data-rate index → data-rate string (DR0–DR5 are valid; 6-15 RFU).
EU868_DR_TABLE: dict[int, str] = {
    0: "SF12BW125",
    1: "SF11BW125",
    2: "SF10BW125",
    3: "SF9BW125",
    4: "SF8BW125",
    5: "SF7BW125",
}

#: EU868 TX power index → dBm value (index 0–7; LoRaWAN 1.0.3 §2.2.3).
EU868_TX_POWER_TABLE: dict[int, int] = {
    0: 14,
    1: 12,
    2: 10,
    3: 8,
    4: 6,
    5: 4,
    6: 2,
    7: 0,
}


# ─── On-air time calculator ───────────────────────────────────────────────────


class AirtimeCalculator:
    """LoRa on-air time calculator (Semtech AN1200.13 formula)."""

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

        t_sym = (2**sf) / bw_hz
        t_preamble = (8 + 4.25) * t_sym

        de = 1 if t_sym >= 0.016 else 0
        cr = 1
        ih = 0
        pl = payload_size_bytes

        num = max(8 * pl - 4 * sf + 28 + 16 - 20 * ih, 0)
        den = 4 * (sf - 2 * de)
        payload_symb_nb = 8 + math.ceil(num / den) * (cr + 4)

        return t_preamble + payload_symb_nb * t_sym


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
        (868_000_000, 868_600_000, 0.01),  # g1: 1 %
        (868_700_000, 869_200_000, 0.001),  # g2: 0.1 %
        (869_400_000, 869_650_000, 0.10),  # g3: 10 %
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

        # ── RX window state (LoRaWAN 1.0.3 §7.2.2 EU868 defaults) ───────────
        self._rx1_dr_offset: int = 0  # RX1DRoffset (0-7)
        self._rx2_data_rate_idx: int = 0  # RX2 data-rate index
        self._rx2_frequency_hz: int = 869_525_000  # EU868 default 869.525 MHz
        self._rx1_delay_sec: float = 1.0  # RECEIVE_DELAY1 (seconds)
        self._nb_trans: int = 1  # Unconfirmed uplink repetitions (1-15)

        # ── Active channel mask (bit i set ↔ channel i is enabled) ───────────
        # EU868 base channels 0-2 are always enabled; bits 0-7 default on.
        self._ch_mask: int = 0x00FF

        # ── Sub-band duty-cycle tracking ──────────────────────────────────────
        # Keyed by sub-band low_hz (from DUTY_CYCLES) or -1 for the default.
        # Stores the earliest monotonic time at which the sub-band may TX again.
        # All channels sharing a regulatory sub-band share one entry here.
        self._subband_available_after: dict[int, float] = {}

        # DutyCycleReq aggregate restriction: 1.0 = no restriction (default).
        # When NS sends DutyCycleReq(MaxDCycle=n>0), fraction = 1/(2^n).
        self._aggregate_dc_fraction: float = 1.0
        self._aggregate_available_after: float = 0.0

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

    @property
    def rx1_delay_sec(self) -> float:
        """RX1 window delay in seconds."""
        return self._rx1_delay_sec

    @property
    def rx2_frequency_hz(self) -> int:
        """RX2 window centre frequency (Hz)."""
        return self._rx2_frequency_hz

    @property
    def rx2_data_rate_idx(self) -> int:
        """RX2 data-rate index."""
        return self._rx2_data_rate_idx

    @property
    def rx1_dr_offset(self) -> int:
        """RX1 data-rate offset."""
        return self._rx1_dr_offset

    @property
    def ch_mask(self) -> int:
        """Active channel mask (bit i set ↔ channel i is enabled)."""
        return self._ch_mask

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
            self._logger.debug("radio_cflist_ignored reason=wrong_length length=%d", len(cflist))
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
        """Return current active uplink channel frequencies (Hz), filtered by the channel mask.

        Channels are indexed from 0: base channels first, then CFList channels.
        A channel at index ``i`` is included only when bit ``i`` of ``_ch_mask`` is set.
        Base channels 0–2 (EU868 mandatory) are always included regardless of mask.
        """
        all_channels = self._base_uplink_channels_hz + self._cflist_channels_hz
        base_len = len(self._base_uplink_channels_hz)
        result: list[int] = []
        for idx, freq_hz in enumerate(all_channels):
            mandatory = idx < base_len  # mandatory base channels always on
            if mandatory or (self._ch_mask >> idx) & 1:
                result.append(freq_hz)
        return result

    # ------------------------------------------------------------------
    # Channel selection — duty-cycle aware
    # ------------------------------------------------------------------

    def select_join_channel(self, attempt_index: int, now: float | None = None) -> RadioTxParams:
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

    def select_uplink_channel(self, uplink_index: int, now: float | None = None) -> RadioTxParams:
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

    def _get_subband_key(self, freq_hz: int) -> int:
        """Return the sub-band key (low_hz) for *freq_hz*, or -1 if not in any defined sub-band."""
        for low, high, _ in self._region.DUTY_CYCLES:
            if low <= freq_hz <= high:
                return low
        return -1

    def can_transmit(self, freq_hz: int, now: float) -> bool:
        """Return ``True`` if *freq_hz* is available for transmission at *now*.

        Checks in order:
        1. Enforcement disabled → always True.
        2. Sub-band availability (shared among all channels in the same ETSI band).
        3. Aggregate duty-cycle availability (from DutyCycleReq, if active).
        """
        if not self._duty_cycle_enforcement:
            return True
        subband_key = self._get_subband_key(freq_hz)
        if subband_key >= 0:
            if now < self._subband_available_after.get(subband_key, 0.0):
                return False
        # Aggregate limit (only applies when NS has sent a DutyCycleReq)
        if self._aggregate_dc_fraction < 1.0:
            if now < self._aggregate_available_after:
                return False
        return True

    def record_transmission(self, freq_hz: int, airtime_sec: float, now: float) -> None:
        """Record a completed transmission and update duty-cycle state.

        Updates:
        - The *sub-band* availability shared by all channels in the same ETSI band.
        - The *aggregate* availability when a DutyCycleReq restriction is active.

        Formula: ``next_tx = now + airtime / duty_cycle``
        (equivalent to ``now + airtime + time_off`` where
        ``time_off = airtime * (1/dc - 1)``).

        Only the **latest** busy-until time is kept per sub-band, so that a second
        transmission within the same sub-band before the first one expires correctly
        extends the cooldown.
        """
        if not self._duty_cycle_enforcement:
            return
        dc = self._get_duty_cycle(freq_hz)
        next_tx = now + airtime_sec / dc

        subband_key = self._get_subband_key(freq_hz)
        if subband_key >= 0:
            self._subband_available_after[subband_key] = max(
                self._subband_available_after.get(subband_key, 0.0),
                next_tx,
            )

        if self._aggregate_dc_fraction < 1.0:
            agg_next_tx = now + airtime_sec / self._aggregate_dc_fraction
            self._aggregate_available_after = max(self._aggregate_available_after, agg_next_tx)

    def next_available_time(self, freq_hz: int, now: float) -> float:
        """Return the earliest monotonic time at which *freq_hz* may be used again.

        Takes sub-band and aggregate restrictions into account.
        """
        if not self._duty_cycle_enforcement:
            return now
        subband_key = self._get_subband_key(freq_hz)
        subband_time = (
            self._subband_available_after.get(subband_key, 0.0) if subband_key >= 0 else 0.0
        )
        agg_time = self._aggregate_available_after if self._aggregate_dc_fraction < 1.0 else 0.0
        return max(subband_time, agg_time, now)

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
    # MAC command application
    # ------------------------------------------------------------------

    def apply_link_adr_req(self, payload: bytes) -> int:
        """Apply a LinkADRReq payload and return the ANS status byte.

        Payload layout (4 bytes, LoRaWAN 1.0.3 §5.2):
        - Byte 0: DataRate_TXPower (DR bits 7-4, TXPower bits 3-0)
        - Byte 1-2: ChMask (little-endian)
        - Byte 3: Redundancy (ChMaskCntl bits 6-4, NbTrans bits 3-0)

        Status byte bit map:
        - bit 0: PowerACK — TX power index was acceptable
        - bit 1: DataRateACK — data-rate index was acceptable
        - bit 2: ChannelMaskACK — channel mask was acceptable

        All three bits must be 1 for the command to be applied.  If any bit
        is 0 the previous state is preserved.

        Returns:
            ACK byte (0x07 = all accepted, 0x00 = all rejected).
        """
        if len(payload) < 4:
            self._logger.warning("apply_link_adr_req: payload too short (%d bytes)", len(payload))
            return 0x00

        dr_tx = payload[0]
        ch_mask = int.from_bytes(payload[1:3], "little")
        redundancy = payload[3]

        dr_idx = (dr_tx >> 4) & 0x0F
        tp_idx = dr_tx & 0x0F
        ch_mask_cntl = (redundancy >> 4) & 0x07
        nb_trans = redundancy & 0x0F

        # Validate data-rate (EU868 valid range 0-5; 0xF = keep-current)
        dr_ack = 0
        new_dr: str | None = None
        if dr_idx == 0x0F:
            dr_ack = 1
            new_dr = self._data_rate  # keep current
        elif dr_idx in EU868_DR_TABLE:
            dr_ack = 1
            new_dr = EU868_DR_TABLE[dr_idx]
        else:
            self._logger.debug("apply_link_adr_req: invalid DR index %d", dr_idx)

        # Validate TX power (EU868 valid range 0-7; 0xF = keep-current)
        tp_ack = 0
        new_tx_power: int | None = None
        if tp_idx == 0x0F:
            tp_ack = 1
            new_tx_power = self._tx_power  # keep current
        elif tp_idx in EU868_TX_POWER_TABLE:
            tp_ack = 1
            new_tx_power = EU868_TX_POWER_TABLE[tp_idx]
        else:
            self._logger.debug("apply_link_adr_req: invalid TX power index %d", tp_idx)

        # Validate channel mask (ChMaskCntl 0 = use ChMask directly for ch 0-15)
        ch_mask_ack = 0
        new_ch_mask: int | None = None
        if ch_mask_cntl == 0:
            # Ensure at least one base channel remains enabled
            base_bits = (1 << len(self._base_uplink_channels_hz)) - 1
            if ch_mask & base_bits:
                ch_mask_ack = 1
                new_ch_mask = ch_mask
            else:
                self._logger.debug(
                    "apply_link_adr_req: ch_mask 0x%04x would disable all base channels",
                    ch_mask,
                )
        elif ch_mask_cntl == 6:
            # All channels on
            ch_mask_ack = 1
            new_ch_mask = 0xFFFF
        else:
            # Other ChMaskCntl values not supported in EU868 base spec
            self._logger.debug("apply_link_adr_req: unsupported ChMaskCntl %d", ch_mask_cntl)

        status = (ch_mask_ack << 2) | (dr_ack << 1) | tp_ack
        if status == 0x07:
            # All three accepted — apply changes
            assert new_dr is not None
            assert new_tx_power is not None
            assert new_ch_mask is not None
            self._data_rate = new_dr
            self._tx_power = new_tx_power
            self._ch_mask = new_ch_mask
            if nb_trans > 0:
                self._nb_trans = nb_trans
            self._logger.info(
                "apply_link_adr_req: accepted dr=%s tx_power=%d ch_mask=0x%04x nb_trans=%d",
                self._data_rate,
                self._tx_power,
                self._ch_mask,
                self._nb_trans,
            )
        else:
            self._logger.info(
                "apply_link_adr_req: rejected status=0x%02x (dr_ack=%d tp_ack=%d ch_ack=%d)",
                status,
                dr_ack,
                tp_ack,
                ch_mask_ack,
            )
        return status

    def apply_rx_param_setup_req(self, payload: bytes) -> int:
        """Apply an RXParamSetupReq payload and return the ANS status byte.

        Payload layout (4 bytes, LoRaWAN 1.0.3 §5.4):
        - Byte 0: DLSettings (RFU bit 7, RX1DRoffset bits 6-4, RX2DataRate bits 3-0)
        - Byte 1-3: Frequency (24-bit little-endian, 100 Hz units)

        Status byte:
        - bit 0: ChannelACK — RX2 frequency is usable
        - bit 1: RX2DataRateACK — RX2 DR is valid
        - bit 2: RX1DRoffsetACK — RX1 DR offset is valid

        All three bits must be 1 for the command to be applied.

        Returns:
            ACK byte (0x07 = all accepted).
        """
        if len(payload) < 4:
            self._logger.warning("apply_rx_param_setup_req: payload too short")
            return 0x00

        dl_settings = payload[0]
        rx1_dr_offset = (dl_settings >> 4) & 0x07
        rx2_dr_idx = dl_settings & 0x0F
        freq_hz = int.from_bytes(payload[1:4], "little") * 100

        # Validate RX1 DR offset (LoRaWAN 1.0.3 §5.4: 0-5 for EU868)
        rx1_offset_ack = 1 if 0 <= rx1_dr_offset <= 5 else 0

        # Validate RX2 DR index
        rx2_dr_ack = 1 if rx2_dr_idx in EU868_DR_TABLE else 0

        # Validate RX2 frequency
        ch_ack = 1 if self._region.FREQ_MIN_HZ <= freq_hz <= self._region.FREQ_MAX_HZ else 0

        status = (rx1_offset_ack << 2) | (rx2_dr_ack << 1) | ch_ack
        if status == 0x07:
            self._rx1_dr_offset = rx1_dr_offset
            self._rx2_data_rate_idx = rx2_dr_idx
            self._rx2_frequency_hz = freq_hz
            self._logger.info(
                "apply_rx_param_setup_req: accepted rx1_offset=%d rx2_dr=%d rx2_freq=%d",
                rx1_dr_offset,
                rx2_dr_idx,
                freq_hz,
            )
        else:
            self._logger.info("apply_rx_param_setup_req: rejected status=0x%02x", status)
        return status

    def apply_new_channel_req(self, payload: bytes) -> int:
        """Apply a NewChannelReq payload and return the ANS status byte.

        Payload layout (5 bytes, LoRaWAN 1.0.3 §5.6):
        - Byte 0: ChIndex (channel index 0-15)
        - Byte 1-3: Freq (24-bit little-endian, 100 Hz units; 0 = disable)
        - Byte 4: DrRange (MaxDR bits 7-4, MinDR bits 3-0)

        Status byte:
        - bit 0: ChannelFreqOK — frequency is within region range
        - bit 1: DataRateRangeOK — DR range is valid

        Returns:
            ACK byte (0x03 = accepted).
        """
        if len(payload) < 5:
            self._logger.warning("apply_new_channel_req: payload too short")
            return 0x00

        ch_index = payload[0]
        freq_hz = int.from_bytes(payload[1:4], "little") * 100
        dr_range = payload[4]
        max_dr = (dr_range >> 4) & 0x0F
        min_dr = dr_range & 0x0F

        # Validate frequency (0 = disable channel)
        if freq_hz == 0:
            freq_ok = 1
            # Remove channel if it was a CFList channel
            if freq_hz in self._cflist_channels_hz:
                self._cflist_channels_hz.remove(freq_hz)
        elif self._region.FREQ_MIN_HZ <= freq_hz <= self._region.FREQ_MAX_HZ:
            freq_ok = 1
        else:
            freq_ok = 0

        # Validate DR range
        dr_ok = (
            1 if (min_dr in EU868_DR_TABLE and max_dr in EU868_DR_TABLE and min_dr <= max_dr) else 0
        )

        status = (dr_ok << 1) | freq_ok
        if status == 0x03 and freq_hz > 0:
            # Only add channels beyond the base 3 (ch_index >= 3 per LoRaWAN spec)
            if ch_index >= len(self._base_uplink_channels_hz):
                if (
                    freq_hz not in self._base_uplink_channels_hz
                    and freq_hz not in self._cflist_channels_hz
                ):
                    self._cflist_channels_hz.append(freq_hz)
                    self._logger.info(
                        "apply_new_channel_req: added ch_index=%d freq=%d", ch_index, freq_hz
                    )
        return status

    def apply_rx_timing_setup_req(self, payload: bytes) -> None:
        """Apply an RXTimingSetupReq payload.

        Payload layout (1 byte, LoRaWAN 1.0.3 §5.7):
        - Byte 0: Settings (Delay bits 3-0; actual RX1 delay = (value if value > 0 else 1) seconds)

        This command always succeeds; the device sends RXTimingSetupAns with no payload.
        """
        if len(payload) < 1:
            self._logger.warning("apply_rx_timing_setup_req: empty payload")
            return
        delay_val = payload[0] & 0x0F
        # Per spec: Del=0 means 1 s
        self._rx1_delay_sec = float(delay_val) if delay_val > 0 else 1.0
        self._logger.info("apply_rx_timing_setup_req: rx1_delay=%.1f s", self._rx1_delay_sec)

    def apply_duty_cycle_req(self, payload: bytes) -> None:
        """Apply a DutyCycleReq payload.

        The MaxDCycle field (bits 3-0) encodes the maximum aggregate duty cycle
        as ``1 / 2^MaxDCycle``.  Value 0 means no restriction (default).

        This implementation records the configured duty cycle but does not
        currently enforce it at the per-sub-band level (the sub-band enforcement
        in :meth:`record_transmission` continues to apply).
        """
        if len(payload) < 1:
            self._logger.warning("apply_duty_cycle_req: empty payload")
            return
        max_dcycle = payload[0] & 0x0F
        if max_dcycle == 0:
            effective = 1.0
        else:
            effective = 1.0 / (2**max_dcycle)
        self._logger.info(
            "apply_duty_cycle_req: max_dcycle=%d effective_fraction=%.6f",
            max_dcycle,
            effective,
        )
        # Store fraction so record_transmission enforces aggregate limit.
        self._aggregate_dc_fraction = effective

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
            key=lambda f: self.next_available_time(f, now),
        )
        wait_sec = self.next_available_time(earliest, now) - now
        if wait_sec > 0:
            self._logger.info("Waiting %.1fs for next available channel", wait_sec)
            _time.sleep(wait_sec)

        actual_now = _time.monotonic()
        self._log_selected(earliest)
        self._reserve(earliest, payload_size, actual_now)
        return RadioTxParams(earliest, self._data_rate, self._tx_power)

    def _reserve(self, freq_hz: int, payload_size: int, now: float) -> None:
        """Record a conservative transmission reservation for duty-cycle tracking."""
        airtime = AirtimeCalculator.calculate(self._data_rate, payload_size)
        self.record_transmission(freq_hz, airtime, now)

    def _log_selected(self, freq_hz: int) -> None:
        self._logger.debug("radio_channel_selected freq_hz=%d", freq_hz)

    def _log_unavailable(self, freq_hz: int) -> None:
        self._logger.debug("radio_channel_unavailable freq_hz=%d reason=duty_cycle", freq_hz)
