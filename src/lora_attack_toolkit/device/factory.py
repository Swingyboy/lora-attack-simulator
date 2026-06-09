from __future__ import annotations

from logging import Logger

from lora_attack_toolkit.device.model import SimulatedDevice
from lora_attack_toolkit.core.schema import DeviceConfig
from lora_attack_toolkit.lorawan.channel_plan import get_channel_plan


def create_device(config: DeviceConfig, logger: Logger | None = None) -> SimulatedDevice:
    device = SimulatedDevice(
        dev_eui=config.activation.dev_eui,
        join_eui=config.activation.join_eui,
        app_key=config.activation.app_key,
        logger=logger,
    )
    device.runtime.channel_plan = get_channel_plan(
        region=config.region,
        duty_cycle_enforcement=config.duty_cycle_enforcement,
        logger=logger,
    )
    return device
