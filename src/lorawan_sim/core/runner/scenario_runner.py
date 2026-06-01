from __future__ import annotations

import time
from logging import Logger
from typing import Callable

from lorawan_sim.domain.device.factory import create_device
from lorawan_sim.domain.device.model import SimulatedDevice
from lorawan_sim.domain.gateway.factory import create_gateway
from lorawan_sim.domain.gateway.model import GatewaySimulator
from lorawan_sim.domain.scenario.schema import DeviceConfig, GatewayConfig
from lorawan_sim.domain.scenario.schema import ScenarioConfig

JOIN_ACCEPT_TIMEOUT_SEC = 20.0
IDLE_SLEEP_SEC = 1.0


class ScenarioRunner:
    def __init__(
        self,
        logger: Logger,
        gateway_factory: Callable[[GatewayConfig, Logger], GatewaySimulator] = create_gateway,
        device_factory: Callable[[DeviceConfig], SimulatedDevice] = create_device,
    ) -> None:
        self._logger = logger
        self._gateway_factory = gateway_factory
        self._device_factory = device_factory

    def run(self, config: ScenarioConfig) -> None:
        gateway = self._gateway_factory(config.gateway, self._logger)
        device = self._device_factory(config.device)
        uplink_payload = bytes.fromhex(config.uplink.payload.value)

        try:
            gateway.start()
            self._logger.info("gateway_started")
            while True:
                if not device.runtime.joined:
                    join_request = device.build_join_request()
                    gateway.forward_uplink(join_request, config.gateway.radio_metadata)
                    self._logger.info("join_request_sent")

                    join_accept = gateway.await_downlink(timeout_sec=JOIN_ACCEPT_TIMEOUT_SEC)
                    if join_accept is None:
                        self._logger.warning("join_accept_timeout")
                        time.sleep(config.uplink.interval_sec)
                        continue

                    try:
                        device.apply_join_accept(join_accept)
                    except ValueError as exc:
                        self._logger.warning("join_accept_invalid", extra={"error": str(exc)})
                        time.sleep(config.uplink.interval_sec)
                        continue
                    self._logger.info("join_completed", extra={"dev_addr": device.runtime.dev_addr_hex})

                if not config.uplink.enabled:
                    time.sleep(IDLE_SLEEP_SEC)
                    continue

                frame = device.build_data_uplink(
                    payload=uplink_payload,
                    f_port=config.uplink.f_port,
                    confirmed=config.uplink.confirmed,
                )
                gateway.forward_uplink(frame, config.gateway.radio_metadata)
                time.sleep(config.uplink.interval_sec)
        finally:
            gateway.stop()
