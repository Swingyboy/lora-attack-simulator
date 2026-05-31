from __future__ import annotations

import base64
import time
from logging import Logger

from lorawan_sim.core.contracts.transport import TransportClient
from lorawan_sim.domain.scenario.schema import RadioMetadata
from lorawan_sim.protocol.semtech.codec import (
    PULL_ACK,
    PULL_RESP,
    PUSH_ACK,
    decode_packet,
    encode_pull_data,
    encode_push_data,
    encode_tx_ack,
)


class GatewaySimulator:
    def __init__(self, gateway_eui: str, transport: TransportClient, logger: Logger) -> None:
        self._gateway_eui = gateway_eui
        self._transport = transport
        self._logger = logger

    def start(self) -> None:
        self._transport.connect()
        self._transport.send(encode_pull_data(self._gateway_eui))

    def stop(self) -> None:
        self._transport.disconnect()

    def forward_uplink(self, phy_payload: bytes, radio: RadioMetadata) -> None:
        rxpk = {
            "rxpk": [
                {
                    "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "tmst": int(time.time() * 1_000_000) & 0xFFFFFFFF,
                    "freq": radio.frequency / 1_000_000,
                    "datr": radio.data_rate,
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
                return downlink_phy
        return None
