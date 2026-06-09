"""Abstract region profile for LoRaWAN radio behaviour.

A :class:`RegionProfile` defines the constants that vary by LoRaWAN
regional specification: base uplink channels, allowed frequency range,
default data rate and TX power.

Concrete subclasses implement region-specific values:

* :class:`~lora_attack_toolkit.radio.eu868.EU868RegionProfile` — EU868

Additional regions (US915, AU915, AS923, …) can be added by subclassing
:class:`RegionProfile` without modifying existing attack or device code.
"""

from __future__ import annotations

from abc import ABC


class RegionProfile(ABC):
    """Static constants describing a LoRaWAN regional radio profile.

    All attributes are class-level constants — subclasses define them as
    class variables so that instances can be shared without copying state.
    """

    #: Short region identifier (e.g. ``"EU868"``).
    REGION_NAME: str

    #: Mandatory base uplink channel frequencies in Hz (never removed by CFList).
    BASE_UPLINK_CHANNELS_HZ: list[int]

    #: Lowest allowed uplink frequency for this region (Hz).
    FREQ_MIN_HZ: int

    #: Highest allowed uplink frequency for this region (Hz).
    FREQ_MAX_HZ: int

    #: Default LoRa data-rate string (e.g. ``"SF7BW125"``).
    DEFAULT_DATA_RATE: str

    #: Default TX power in dBm.
    DEFAULT_TX_POWER: int
