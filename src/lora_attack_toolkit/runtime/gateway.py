from __future__ import annotations

import base64
import time
from logging import Logger
from typing import TYPE_CHECKING

from lora_attack_toolkit.config import GatewayConfig, RadioMetadata
from lora_attack_toolkit.lorawan.semtech_udp import (
    PULL_ACK,
    PULL_RESP,
    PUSH_ACK,
    decode_packet,
    encode_pull_data,
    encode_push_data,
    encode_tx_ack,
)
from lora_attack_toolkit.transport.resilient import ResilientTransport
from lora_attack_toolkit.transport.retry import RetryPolicy
from lora_attack_toolkit.transport.transport import TransportClient
from lora_attack_toolkit.transport.udp import UdpTransport


class GatewaySimulator:
    def __init__(
        self,
        gateway_eui: str,
        transport: TransportClient,
        logger: Logger,
        pull_data_interval_sec: int = 5,
    ) -> None:
        self._gateway_eui = gateway_eui
        self._transport = transport
        self._logger = logger
        self._pull_data_interval_sec = pull_data_interval_sec
        self._next_pull_data_at = 0.0

    def _send_pull_data(self) -> None:
        self._transport.send(encode_pull_data(self._gateway_eui))
        self._next_pull_data_at = time.monotonic() + self._pull_data_interval_sec

    def _send_periodic_pull_data_if_due(self) -> None:
        if time.monotonic() >= self._next_pull_data_at:
            self._send_pull_data()

    def start(self) -> None:
        self._transport.connect()
        self._send_pull_data()

    def stop(self) -> None:
        self._transport.disconnect()

    def forward_uplink(self, phy_payload: bytes, radio: RadioMetadata) -> None:
        self._send_periodic_pull_data_if_due()
        rxpk = {
            "rxpk": [
                {
                    "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "tmst": int(time.time() * 1_000_000) & 0xFFFFFFFF,
                    "chan": 0,
                    "rfch": 0,
                    "freq": radio.frequency / 1_000_000,
                    "stat": 1,
                    "modu": "LORA",
                    "datr": radio.data_rate,
                    "codr": "4/5",
                    "rssi": radio.rssi,
                    "lsnr": radio.snr,
                    "size": len(phy_payload),
                    "data": base64.b64encode(phy_payload).decode("ascii"),
                }
            ]
        }
        packet = encode_push_data(self._gateway_eui, rxpk)
        self._transport.send(packet)
        self._logger.info("push_data_sent")

    def await_downlink(self, timeout_sec: float) -> bytes | None:
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            self._send_periodic_pull_data_if_due()
            pkt = self._transport.receive(timeout_sec=0.3)
            if pkt is None:
                continue
            semtech = decode_packet(pkt)
            if semtech.packet_type in (PULL_ACK, PUSH_ACK):
                continue
            if semtech.packet_type == PULL_RESP and semtech.json_body:
                txpk = semtech.json_body.get("txpk", {})
                if "data" not in txpk:
                    continue
                downlink_phy = base64.b64decode(txpk["data"])
                self._transport.send(encode_tx_ack(semtech.token, self._gateway_eui))
                self._logger.info("downlink_received")
                self._logger.debug("Downlink %s...", downlink_phy.hex()[:32])
                return downlink_phy
        return None
    
    def drain_downlinks(self, drain_time_sec: float = 1.0) -> int:
        """
        Drain any pending downlinks from the queue.
        
        This is useful to clear responses from previous uplinks
        before waiting for a specific downlink response.
        
        Args:
            drain_time_sec: How long to drain (seconds)
            
        Returns:
            Number of downlinks drained
        """
        drained_count = 0
        deadline = time.monotonic() + drain_time_sec
        
        while time.monotonic() < deadline:
            self._send_periodic_pull_data_if_due()
            pkt = self._transport.receive(timeout_sec=0.1)
            if pkt is None:
                continue
            
            semtech = decode_packet(pkt)
            if semtech.packet_type in (PULL_ACK, PUSH_ACK):
                continue
            if semtech.packet_type == PULL_RESP and semtech.json_body:
                txpk = semtech.json_body.get("txpk", {})
                if "data" in txpk:
                    downlink_phy = base64.b64decode(txpk["data"])
                    self._transport.send(encode_tx_ack(semtech.token, self._gateway_eui))
                    drained_count += 1
                    self._logger.debug(
                        "Drained downlink %d: %s...", drained_count, downlink_phy.hex()[:32]
                    )
        
        if drained_count > 0:
            self._logger.info("Drained %s pending downlink(s)", drained_count)
        
        return drained_count


# --- factory ---

if TYPE_CHECKING:
    from lora_attack_toolkit.config import GatewayConfigV1, TargetConfig


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
