from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from logging import Logger
from typing import TYPE_CHECKING, Any

from lora_attack_toolkit.config import RadioMetadata
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


@dataclass(frozen=True)
class ReceivedDownlink:
    """A downlink decoded from a Semtech ``PULL_RESP`` ``txpk`` object.

    Carries the metadata needed for RX-window matching, attribution evidence,
    and result export, rather than discarding everything but the PHY payload.

    Note: the simulator transport is a *limited Semtech UDP packet forwarder*.
    Fields such as ``concentrator_timestamp`` reflect whatever the Network
    Server scheduled in ``txpk`` and may be absent (``None``) for servers that
    omit them.
    """

    phy_payload: bytes
    token: bytes
    frequency_hz: int | None
    data_rate: str | None
    concentrator_timestamp: int | None
    received_monotonic: float
    raw_txpk: dict[str, Any] = field(default_factory=dict)


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

    def _decode_txpk(self, txpk: dict[str, Any]) -> ReceivedDownlink:
        """Build a :class:`ReceivedDownlink` from a decoded ``txpk`` object."""
        freq = txpk.get("freq")
        return ReceivedDownlink(
            phy_payload=base64.b64decode(txpk["data"]),
            token=b"",  # overwritten by the caller that knows the Semtech token
            frequency_hz=int(round(float(freq) * 1_000_000)) if freq is not None else None,
            data_rate=txpk.get("datr"),
            concentrator_timestamp=txpk.get("tmst"),
            received_monotonic=time.monotonic(),
            raw_txpk=dict(txpk),
        )

    def await_downlink_structured(self, timeout_sec: float) -> ReceivedDownlink | None:
        """Wait for a downlink and return it as a structured :class:`ReceivedDownlink`.

        Unlike :meth:`await_downlink` (which returns only the PHY payload), this
        preserves the Semtech ``txpk`` metadata — concentrator timestamp,
        frequency, data rate, and token — for RX-window matching, attribution
        evidence, and export.
        """
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
                downlink = self._decode_txpk(txpk)
                # The Semtech token is carried on the packet, not in txpk.
                downlink = ReceivedDownlink(
                    phy_payload=downlink.phy_payload,
                    token=semtech.token,
                    frequency_hz=downlink.frequency_hz,
                    data_rate=downlink.data_rate,
                    concentrator_timestamp=downlink.concentrator_timestamp,
                    received_monotonic=downlink.received_monotonic,
                    raw_txpk=downlink.raw_txpk,
                )
                self._transport.send(encode_tx_ack(semtech.token, self._gateway_eui))
                self._logger.info("downlink_received")
                self._logger.debug("Downlink %s...", downlink.phy_payload.hex()[:32])
                return downlink
        return None

    def await_downlink(self, timeout_sec: float) -> bytes | None:
        downlink = self.await_downlink_structured(timeout_sec)
        return downlink.phy_payload if downlink is not None else None

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
    config: tuple["GatewayConfigV1", "TargetConfig"],
    logger: Logger,
) -> GatewaySimulator:
    """Create a gateway simulator from a v1 config tuple.

    The underlying UDP socket is wrapped with :class:`ResilientTransport` so
    that transient DNS failures, network blips, and socket resets are handled
    transparently with exponential back-off retry — without any changes to
    attack implementations.

    Args:
        config: Tuple of (GatewayConfigV1, TargetConfig) from the loaded scenario.
        logger: Logger instance passed to both the gateway and the resilient transport.

    Returns:
        GatewaySimulator instance backed by a resilient transport.
    """
    policy = RetryPolicy()  # internal defaults: 3 attempts, 2 s backoff
    gateway_cfg, target_cfg = config
    inner = UdpTransport(target_cfg.host, target_cfg.port)
    transport = ResilientTransport(inner, policy=policy, logger=logger)
    return GatewaySimulator(
        gateway_eui=gateway_cfg.gateway_eui,
        transport=transport,
        logger=logger,
        pull_data_interval_sec=gateway_cfg.pull_data_interval_sec,
    )
