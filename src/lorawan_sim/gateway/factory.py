from __future__ import annotations

from logging import Logger

from lorawan_sim.gateway.model import GatewaySimulator
from lorawan_sim.scenario.schema import GatewayConfig
from lorawan_sim.transport.udp import UdpTransport


def create_gateway(config: GatewayConfig, logger: Logger) -> GatewaySimulator:
    transport = UdpTransport(config.semtech_udp.host, config.semtech_udp.port)
    return GatewaySimulator(
        gateway_eui=config.gateway_eui,
        transport=transport,
        logger=logger,
    )
