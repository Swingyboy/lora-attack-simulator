from __future__ import annotations

from logging import Logger

from lorawan_sim.adapters.transport.udp import UdpTransport
from lorawan_sim.domain.gateway.model import GatewaySimulator
from lorawan_sim.domain.scenario.schema import GatewayConfig


def create_gateway(config: GatewayConfig, logger: Logger) -> GatewaySimulator:
    transport = UdpTransport(config.semtech_udp.host, config.semtech_udp.port)
    return GatewaySimulator(
        gateway_eui=config.gateway_eui,
        transport=transport,
        logger=logger,
    )
