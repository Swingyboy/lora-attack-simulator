"""LoRaWAN Class A device receive-window logic.

Implements the Class A RX1/RX2 downlink reception model:

* RX1 opens ``rx1_delay`` seconds after an uplink TX.
* RX2 opens ``rx1_delay + 1`` seconds after an uplink TX.
* RX1 data-rate = ``max(0, uplink_DR_index - rx1_dr_offset)`` (EU868).
* RX2 data-rate and frequency come from the Radio's configured state.
* When a valid downlink is accepted in RX1, RX2 is *not* opened.
* An uplink must not be sent until RX2 has expired or a valid frame
  was accepted.

All timing uses monotonic time via the injected :class:`SimClock`.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from lora_attack_toolkit.lorawan.radio import EU868_DR_TABLE, Radio
from lora_attack_toolkit.lorawan.time_utils import SimClock, WallClock, interruptible_sleep

if TYPE_CHECKING:
    from lora_attack_toolkit.runtime.gateway import GatewaySimulator


# ── RX window outcome ─────────────────────────────────────────────────────────


class RxWindow(str, Enum):
    """Which receive window accepted the downlink, or why none did."""

    RX1 = "rx1"
    RX2 = "rx2"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class RxWindowResult:
    """Result of a Class A receive-window cycle.

    Attributes
    ----------
    window:
        Which window accepted the downlink, or TIMEOUT/CANCELLED.
    downlink_frame:
        Raw PHY payload bytes of the accepted downlink, or ``None``.
    rx1_freq_hz:
        Expected RX1 frequency (Hz).
    rx1_data_rate:
        Expected RX1 data-rate string (e.g. ``"SF7BW125"``).
    rx2_freq_hz:
        Expected RX2 frequency (Hz).
    rx2_data_rate:
        Expected RX2 data-rate string.
    rx1_opened_at:
        Monotonic time when RX1 was opened.
    rx2_opened_at:
        Monotonic time when RX2 was opened (``None`` if RX1 succeeded).
    """

    window: RxWindow
    downlink_frame: bytes | None = None
    rx1_freq_hz: int = 0
    rx1_data_rate: str = ""
    rx2_freq_hz: int = 0
    rx2_data_rate: str = ""
    rx1_opened_at: float = 0.0
    rx2_opened_at: float | None = None

    @property
    def accepted(self) -> bool:
        """True when a valid downlink was received in RX1 or RX2."""
        return self.window in (RxWindow.RX1, RxWindow.RX2)


# ── EU868 RX1 DR derivation ───────────────────────────────────────────────────

_EU868_RX1_DR_TABLE: dict[int, dict[int, int]] = {
    # uplink_dr_idx: { rx1_dr_offset: rx1_dr_idx }
    # LoRaWAN 1.0.3 Regional Parameters §2.2.7 Table 2
    5: {0: 5, 1: 4, 2: 3, 3: 2, 4: 1, 5: 0},
    4: {0: 4, 1: 3, 2: 2, 3: 1, 4: 0, 5: 0},
    3: {0: 3, 1: 2, 2: 1, 3: 0, 4: 0, 5: 0},
    2: {0: 2, 1: 1, 2: 0, 3: 0, 4: 0, 5: 0},
    1: {0: 1, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
    0: {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
}


def eu868_rx1_data_rate(uplink_dr_str: str, rx1_dr_offset: int) -> str:
    """Derive the EU868 RX1 data-rate string from an uplink DR and offset.

    Args:
        uplink_dr_str: Data-rate string used for the uplink, e.g. ``"SF7BW125"``.
        rx1_dr_offset: The RX1DRoffset configured in the device (0–5).

    Returns:
        The RX1 data-rate string.

    Raises:
        ValueError: If *uplink_dr_str* is not a valid EU868 DR or the offset
            is out of range.
    """
    # Reverse-look up the uplink DR index
    uplink_dr_idx: int | None = None
    for idx, dr_str in EU868_DR_TABLE.items():
        if dr_str == uplink_dr_str:
            uplink_dr_idx = idx
            break
    if uplink_dr_idx is None:
        raise ValueError("eu868_rx1_data_rate: unknown uplink data-rate %r" % uplink_dr_str)
    if rx1_dr_offset < 0 or rx1_dr_offset > 5:
        raise ValueError("eu868_rx1_data_rate: rx1_dr_offset must be 0–5, got %d" % rx1_dr_offset)
    rx1_dr_idx = _EU868_RX1_DR_TABLE[uplink_dr_idx].get(rx1_dr_offset, 0)
    return EU868_DR_TABLE[rx1_dr_idx]


# ── ClassAReceiver ────────────────────────────────────────────────────────────


class ClassAReceiver:
    """Orchestrates Class A RX1/RX2 downlink reception for a single uplink.

    Usage::

        receiver = ClassAReceiver(radio, gateway)
        result = receiver.await_downlink(
            uplink_freq_hz=868_100_000,
            uplink_dr_str="SF7BW125",
            tx_monotonic=time.monotonic(),
            cancel_event=ctx.cancel_event,
        )
        if result.accepted:
            device.apply_downlink(result.downlink_frame)

    Parameters
    ----------
    radio:
        :class:`Radio` instance providing RX state (delays, DR offsets,
        RX2 frequency and data-rate).
    gateway:
        Gateway used to poll for incoming downlinks.
    clock:
        Injectable :class:`SimClock`; defaults to the wall clock.
    rx_window_sec:
        How long each RX window stays open while polling for a downlink.
        Default is 0.5 s (adequate for UDP-based simulation).
    """

    def __init__(
        self,
        radio: Radio,
        gateway: "GatewaySimulator",
        clock: SimClock | None = None,
        rx_window_sec: float = 0.5,
    ) -> None:
        self._radio = radio
        self._gateway = gateway
        self._clock = clock or WallClock()
        self._rx_window_sec = rx_window_sec

    def await_downlink(
        self,
        uplink_freq_hz: int,
        uplink_dr_str: str,
        tx_monotonic: float,
        cancel_event: threading.Event | None = None,
    ) -> RxWindowResult:
        """Wait for a Class A downlink in RX1, then optionally RX2.

        This method **blocks** until:
        * A downlink frame is received in RX1 or RX2, or
        * RX2 expires without a frame, or
        * *cancel_event* is set.

        Args:
            uplink_freq_hz: Frequency used for the preceding uplink (Hz).
            uplink_dr_str: Data-rate string used for the preceding uplink.
            tx_monotonic: Monotonic timestamp at which the uplink was sent.
            cancel_event: Optional cancellation signal.

        Returns:
            :class:`RxWindowResult` describing the outcome.
        """
        rx1_delay = self._radio.rx1_delay_sec
        rx2_delay = rx1_delay + 1.0

        rx1_dr_str = eu868_rx1_data_rate(uplink_dr_str, self._radio.rx1_dr_offset)
        rx2_dr_str = EU868_DR_TABLE.get(self._radio.rx2_data_rate_idx, "SF12BW125")
        rx2_freq = self._radio.rx2_frequency_hz

        result = RxWindowResult(
            window=RxWindow.TIMEOUT,
            rx1_freq_hz=uplink_freq_hz,
            rx1_data_rate=rx1_dr_str,
            rx2_freq_hz=rx2_freq,
            rx2_data_rate=rx2_dr_str,
        )

        # ── Wait until RX1 opens ──────────────────────────────────────────────
        now = self._clock.monotonic()
        wait_to_rx1 = (tx_monotonic + rx1_delay) - now
        if wait_to_rx1 > 0:
            if not interruptible_sleep(wait_to_rx1, cancel_event):
                result.window = RxWindow.CANCELLED
                return result

        # ── Poll RX1 window ───────────────────────────────────────────────────
        result.rx1_opened_at = self._clock.monotonic()
        frame = self._gateway.await_downlink(timeout_sec=self._rx_window_sec)
        if frame is not None:
            result.window = RxWindow.RX1
            result.downlink_frame = frame
            return result

        if cancel_event is not None and cancel_event.is_set():
            result.window = RxWindow.CANCELLED
            return result

        # ── Wait for RX2 to open (additional ~0.5 s gap after RX1) ──────────
        now = self._clock.monotonic()
        rx2_open_at = tx_monotonic + rx2_delay
        wait_to_rx2 = rx2_open_at - now
        if wait_to_rx2 > 0:
            if not interruptible_sleep(wait_to_rx2, cancel_event):
                result.window = RxWindow.CANCELLED
                return result

        # ── Poll RX2 window ───────────────────────────────────────────────────
        result.rx2_opened_at = self._clock.monotonic()
        frame = self._gateway.await_downlink(timeout_sec=self._rx_window_sec)
        if frame is not None:
            result.window = RxWindow.RX2
            result.downlink_frame = frame

        return result
