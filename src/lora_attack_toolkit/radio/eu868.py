"""EU868 regional radio profile (LoRaWAN Regional Parameters v1.0.3 §2.2)."""

from __future__ import annotations

from lora_attack_toolkit.radio.regions import RegionProfile


class EU868RegionProfile(RegionProfile):
    """EU868 regional constants.

    Base uplink channels (always preserved):
        868.1 / 868.3 / 868.5 MHz

    Allowed CFList frequency range:
        863 – 870 MHz  (ETSI EN 300 220-2 sub-bands g, g1, g2, g3)

    Default DR / power:
        SF7BW125 / 14 dBm
    """

    REGION_NAME = "EU868"
    BASE_UPLINK_CHANNELS_HZ: list[int] = [868_100_000, 868_300_000, 868_500_000]
    FREQ_MIN_HZ: int = 863_000_000
    FREQ_MAX_HZ: int = 870_000_000
    DEFAULT_DATA_RATE: str = "SF7BW125"
    DEFAULT_TX_POWER: int = 14
