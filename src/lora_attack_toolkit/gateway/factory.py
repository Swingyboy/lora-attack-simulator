from __future__ import annotations

from logging import Logger
from typing import TYPE_CHECKING

from lora_attack_toolkit.transport.resilient import ResilientTransport
from lora_attack_toolkit.transport.retry import RetryPolicy
from lora_attack_toolkit.transport.udp import UdpTransport
from lora_attack_toolkit.gateway.model import GatewaySimulator
from lora_attack_toolkit.core.schema import GatewayConfig

if TYPE_CHECKING:
    from lora_attack_toolkit.core.schema_v1 import GatewayConfigV1, TargetConfig


def create_gateway(
    config: GatewayConfig | tuple["GatewayConfigV1", "TargetConfig"],
    logger: Logger,
) -> GatewaySimulator:
    """Create gateway simulator from config.

    The underlying UDP socket is wrapped with :class:`ResilientTransport` so
    that transient DNS failures, network blips, and socket resets are handled
    transparently with exponential back-off retry — without any changes to
    attack implementations.

    Args:
        config: Either GatewayConfig (v0.9) or tuple of (GatewayConfigV1, TargetConfig) for v1.0
        logger: Logger instance passed to both the gateway and the resilient transport

    Returns:
        GatewaySimulator instance backed by a resilient transport
    """
    policy = RetryPolicy()  # internal defaults: 3 attempts, 2 s backoff

    if isinstance(config, tuple):
        gateway_cfg, target_cfg = config
        inner = UdpTransport(target_cfg.host, target_cfg.port)
        transport = ResilientTransport(inner, policy=policy, logger=logger)
        return GatewaySimulator(
            gateway_eui=gateway_cfg.gateway_eui,
            transport=transport,
            logger=logger,
            pull_data_interval_sec=gateway_cfg.pull_data_interval_sec,
        )

    inner = UdpTransport(config.semtech_udp.host, config.semtech_udp.port)
    transport = ResilientTransport(inner, policy=policy, logger=logger)
    return GatewaySimulator(
        gateway_eui=config.gateway_eui,
        transport=transport,
        logger=logger,
        pull_data_interval_sec=config.semtech_udp.pull_data_interval_sec,
    )
