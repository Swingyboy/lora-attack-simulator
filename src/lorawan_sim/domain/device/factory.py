from __future__ import annotations

from lorawan_sim.domain.device.model import SimulatedDevice
from lorawan_sim.domain.scenario.schema import DeviceConfig


def create_device(config: DeviceConfig) -> SimulatedDevice:
    return SimulatedDevice(
        dev_eui=config.activation.dev_eui,
        join_eui=config.activation.join_eui,
        app_key=config.activation.app_key,
    )
