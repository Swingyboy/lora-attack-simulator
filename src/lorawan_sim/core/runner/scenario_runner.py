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
from lorawan_sim.domain.strategy.periodic_uplink import PeriodicUplinkStrategy


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

        started = time.monotonic()
        try:
            gateway.start()
            self._logger.info("gateway_started")

            join_request = device.build_join_request()
            gateway.forward_uplink(join_request, config.gateway.radio_metadata)
            self._logger.info("join_request_sent")

            join_accept = gateway.await_downlink(timeout_sec=10.0)
            if join_accept is None:
                raise RuntimeError("join accept was not received from network side")

            device.apply_join_accept(join_accept)
            self._logger.info("join_completed", extra={"dev_addr": device.runtime.dev_addr_hex})

            if config.uplink.enabled:
                uplink = PeriodicUplinkStrategy(
                    interval_sec=config.uplink.interval_sec,
                    count=config.uplink.count,
                    payload=bytes.fromhex(config.uplink.payload.value),
                    f_port=config.uplink.f_port,
                    confirmed=config.uplink.confirmed,
                )
                for frame in uplink.generate(device):
                    gateway.forward_uplink(frame, config.gateway.radio_metadata)

            runtime = time.monotonic() - started
            if runtime > config.scenario.duration_sec:
                self._logger.warning("duration_limit_exceeded", extra={"runtime_sec": runtime})
        finally:
            gateway.stop()
