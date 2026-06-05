from __future__ import annotations

from lora_attack_toolkit.device.model import SimulatedDevice
from lora_attack_toolkit.core.schema import DeviceConfig


def create_device(config: DeviceConfig) -> SimulatedDevice:
    return SimulatedDevice(
        dev_eui=config.activation.dev_eui,
        join_eui=config.activation.join_eui,
        app_key=config.activation.app_key,
    )
