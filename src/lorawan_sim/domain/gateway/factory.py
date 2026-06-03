from __future__ import annotations

from logging import Logger
from typing import TYPE_CHECKING

from lorawan_sim.adapters.transport.udp import UdpTransport
from lorawan_sim.domain.gateway.model import GatewaySimulator
from lorawan_sim.domain.scenario.schema import GatewayConfig

if TYPE_CHECKING:
    from lorawan_sim.domain.attack_scenario.schema_v1 import GatewayConfigV1, TargetConfig


def create_gateway(
    config: GatewayConfig | tuple["GatewayConfigV1", "TargetConfig"],
    logger: Logger,
) -> GatewaySimulator:
    """Create gateway simulator from config.
    
    Args:
        config: Either GatewayConfig (v0.9) or tuple of (GatewayConfigV1, TargetConfig) for v1.0
        logger: Logger instance
        
    Returns:
        GatewaySimulator instance
    """
    # Handle v1.0 format (GatewayConfigV1 + TargetConfig)
    if isinstance(config, tuple):
        gateway_cfg, target_cfg = config
        transport = UdpTransport(target_cfg.host, target_cfg.port)
        return GatewaySimulator(
            gateway_eui=gateway_cfg.gateway_eui,
            transport=transport,
            logger=logger,
            pull_data_interval_sec=gateway_cfg.pull_data_interval_sec,
        )
    
    # Handle v0.9 format (GatewayConfig)
    transport = UdpTransport(config.semtech_udp.host, config.semtech_udp.port)
    return GatewaySimulator(
        gateway_eui=config.gateway_eui,
        transport=transport,
        logger=logger,
        pull_data_interval_sec=config.semtech_udp.pull_data_interval_sec,
    )
