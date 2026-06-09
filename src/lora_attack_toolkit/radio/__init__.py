"""Radio abstraction layer.

Provides a device-facing API for managing simulated radio state:
channel selection, CFList processing, data-rate / TX-power state, and
future MAC-command / ADR integration.

Public API
----------
* :class:`~lora_attack_toolkit.radio.radio.Radio` — stateful radio instance
* :class:`~lora_attack_toolkit.radio.regions.RegionProfile` — abstract region base
* :class:`~lora_attack_toolkit.radio.eu868.EU868RegionProfile` — EU868 parameters
"""

from lora_attack_toolkit.radio.eu868 import EU868RegionProfile
from lora_attack_toolkit.radio.radio import Radio
from lora_attack_toolkit.radio.regions import RegionProfile

__all__ = ["Radio", "RegionProfile", "EU868RegionProfile"]
