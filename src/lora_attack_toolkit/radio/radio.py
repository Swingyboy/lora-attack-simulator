"""Simulated device radio state.

:class:`Radio` is the single source of truth for a device's radio
configuration during an attack session.  Attack and device code should
ask the radio for channel frequencies and data-rate / TX-power parameters
rather than manipulating lists directly.

Responsibilities
----------------
* Region-specific default uplink channels (always preserved).
* CFList-derived additional channels (replaced on each valid new CFList).
* Current data rate and TX power state.
* Round-robin uplink channel selection.
* Future: MAC-command / ADR driven state changes.

CFList replacement model
------------------------
::

    active_channels = base_channels + latest_cflist_channels

Each valid Type 0 CFList completely replaces the previous CFList-derived
channels; channels never accumulate across multiple JoinAccept messages.
"""

from __future__ import annotations

import logging
from logging import Logger
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lora_attack_toolkit.lorawan.protocol.mac_commands import MACCommand

from lora_attack_toolkit.radio.regions import RegionProfile


class Radio:
    """Simulated device radio.

    Parameters
    ----------
    region:
        Region profile that supplies base channels, allowed frequency range,
        and default data-rate / TX-power values.
    logger:
        Optional logger for radio state-change events.
    """

    def __init__(
        self,
        region: RegionProfile,
        logger: Logger | None = None,
    ) -> None:
        self._region = region
        self._base_uplink_channels_hz: list[int] = list(region.BASE_UPLINK_CHANNELS_HZ)
        self._cflist_channels_hz: list[int] = []
        self._data_rate: str = region.DEFAULT_DATA_RATE
        self._tx_power: int = region.DEFAULT_TX_POWER
        self._uplink_index: int = 0
        self._logger = logger or logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Read-only properties
    # ------------------------------------------------------------------

    @property
    def region_name(self) -> str:
        return self._region.REGION_NAME

    # ------------------------------------------------------------------
    # Channel selection
    # ------------------------------------------------------------------

    def get_active_uplink_channels(self) -> list[int]:
        """Return current active uplink channel frequencies in Hz.

        Always includes base channels; CFList-derived channels follow when set.
        """
        return self._base_uplink_channels_hz + self._cflist_channels_hz

    def get_next_uplink_channel(self) -> int:
        """Return the frequency of the next uplink channel (round-robin).

        The internal counter is advanced on each call so consecutive calls
        cycle through all active channels.
        """
        channels = self.get_active_uplink_channels()
        freq = channels[self._uplink_index % len(channels)]
        self._uplink_index += 1
        return freq

    # ------------------------------------------------------------------
    # CFList
    # ------------------------------------------------------------------

    def apply_cflist(self, cflist: bytes | None) -> None:
        """Parse and apply a JoinAccept CFList (Type 0 — frequency list).

        The parsed frequencies *replace* any previously learned CFList
        channels.  Base channels are never modified.

        CFList layout (16 bytes):
          bytes  0-2:  freq[0]  (3 bytes, little-endian, unit = 100 Hz)
          bytes  3-5:  freq[1]
          bytes  6-8:  freq[2]
          bytes  9-11: freq[3]
          bytes 12-14: freq[4]
          byte  15:    CFListType (0 = frequency list)

        Ignored without mutating radio state:
          * ``None``
          * length ≠ 16
          * CFListType ≠ 0
        """
        if cflist is None:
            self._logger.debug(
                "radio_cflist_ignored region=%s reason=none", self._region.REGION_NAME
            )
            return

        if len(cflist) != 16:
            self._logger.debug(
                "radio_cflist_ignored region=%s reason=wrong_length length=%d",
                self._region.REGION_NAME,
                len(cflist),
            )
            return

        cflist_type = cflist[15]
        if cflist_type != 0:
            self._logger.debug(
                "radio_cflist_ignored region=%s reason=unsupported_type cflist_type=%d",
                self._region.REGION_NAME,
                cflist_type,
            )
            return

        base = set(self._base_uplink_channels_hz)
        seen: set[int] = set()
        new_cflist: list[int] = []

        for i in range(5):
            raw = cflist[i * 3 : i * 3 + 3]
            value = int.from_bytes(raw, "little")
            if value == 0:
                continue  # unused slot
            freq_hz = value * 100
            if not (self._region.FREQ_MIN_HZ <= freq_hz <= self._region.FREQ_MAX_HZ):
                self._logger.debug(
                    "radio_cflist_ignored_freq region=%s freq_hz=%d reason=out_of_range",
                    self._region.REGION_NAME,
                    freq_hz,
                )
                continue
            if freq_hz in base:
                continue  # already a base channel — no need to add
            if freq_hz in seen:
                continue  # duplicate within this CFList
            new_cflist.append(freq_hz)
            seen.add(freq_hz)

        # Replace (not append) previous CFList-derived channels.
        self._cflist_channels_hz = new_cflist

        self._logger.info(
            "radio_cflist_applied region=%s base=%s cflist=%s active=%s",
            self._region.REGION_NAME,
            self._base_uplink_channels_hz,
            self._cflist_channels_hz,
            self.get_active_uplink_channels(),
        )

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

    def apply_mac_command(self, command: "MACCommand") -> None:  # noqa: F821
        """Apply a radio-affecting MAC command.

        Not yet implemented — placeholder for future LinkADRReq,
        NewChannelReq, RXParamSetupReq, and DutyCycleReq support.
        """

    def apply_adr_settings(
        self,
        data_rate: int | None = None,
        tx_power: int | None = None,
    ) -> None:
        """Apply ADR-driven data-rate and TX-power changes.

        Not yet implemented — placeholder for future ADR integration.
        """
