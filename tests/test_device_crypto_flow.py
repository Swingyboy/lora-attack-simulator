from __future__ import annotations

import base64
import json
import logging
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from transport.in_memory import InMemoryTransport
from lorawan.device.model import SimulatedDevice
from lorawan.gateway.model import GatewaySimulator
from lorawan.scenario.schema import RadioMetadata


def _build_join_accept(app_key_hex: str, dev_addr_hex: str) -> bytes:
    app_key = bytes.fromhex(app_key_hex)
    app_nonce = bytes.fromhex("010203")
    net_id = bytes.fromhex("000102")
    dev_addr_le = bytes.fromhex(dev_addr_hex)[::-1]
    dl_settings = bytes([0x00])
    rx_delay = bytes([0x01])
    plain_wo_mic = app_nonce + net_id + dev_addr_le + dl_settings + rx_delay

    from lorawan.protocol.crypto_v103 import aes_cmac_4

    mhdr = bytes([0x20])
    mic = aes_cmac_4(app_key, mhdr + plain_wo_mic)
    plain = plain_wo_mic + mic
    cipher = Cipher(algorithms.AES(app_key), modes.ECB())
    decryptor = cipher.decryptor()
    encrypted = decryptor.update(plain) + decryptor.finalize()
    return mhdr + encrypted


class DeviceCryptoFlowTests(unittest.TestCase):
    def test_device_join_and_uplink_build(self) -> None:
        app_key = "00112233445566778899aabbccddeeff"
        device = SimulatedDevice(
            dev_eui="0011223344556677",
            join_eui="0102030405060708",
            app_key=app_key,
        )

        join_req = device.build_join_request()
        self.assertEqual(join_req[0], 0x00)

        join_accept = _build_join_accept(app_key, "26011BDA")
        device.apply_join_accept(join_accept)
        self.assertTrue(device.runtime.joined)
        self.assertEqual(device.runtime.dev_addr_hex, "26011bda")

        uplink = device.build_data_uplink(payload=b"\x01\x02\x03", f_port=10, confirmed=False)
        self.assertEqual(uplink[0], 0x40)
        self.assertEqual(device.runtime.fcnt_up, 1)

    def test_gateway_reads_pull_resp(self) -> None:
        app_key = "00112233445566778899aabbccddeeff"
        join_accept = _build_join_accept(app_key, "26011BDA")

        transport = InMemoryTransport()
        gateway = GatewaySimulator(
            gateway_eui="0102030405060708",
            transport=transport,
            logger=logging.getLogger("test"),
        )

        token = b"\x12\x34"
        pull_resp = (
            bytes([2])
            + token
            + bytes([0x03])
            + json.dumps({"txpk": {"data": base64.b64encode(join_accept).decode()}}).encode()
        )

        gateway.start()
        transport.queue_incoming(pull_resp)
        dl = gateway.await_downlink(timeout_sec=0.5)
        self.assertEqual(dl, join_accept)
        self.assertGreaterEqual(len(transport.sent_packets), 2)
        gateway.stop()

    def test_gateway_wraps_uplink_as_push_data(self) -> None:
        transport = InMemoryTransport()
        gateway = GatewaySimulator(
            gateway_eui="0102030405060708",
            transport=transport,
            logger=logging.getLogger("test"),
        )
        gateway.start()
        gateway.forward_uplink(
            b"\x40\x00",
            RadioMetadata(
                frequency=868100000,
                data_rate="SF7BW125",
                rssi=-60,
                snr=7.5,
            ),
        )
        self.assertTrue(any(packet[3] == 0x00 for packet in transport.sent_packets))
        gateway.stop()

    def test_gateway_sends_periodic_pull_data(self) -> None:
        transport = InMemoryTransport()
        gateway = GatewaySimulator(
            gateway_eui="0102030405060708",
            transport=transport,
            logger=logging.getLogger("test"),
            pull_data_interval_sec=1,
        )
        radio = RadioMetadata(
            frequency=868100000,
            data_rate="SF7BW125",
            rssi=-60,
            snr=7.5,
        )
        with patch(
            "lorawan.gateway.model.time.monotonic",
            side_effect=[0.0, 0.2, 1.1, 1.1],
        ):
            gateway.start()
            gateway.forward_uplink(b"\x40\x00", radio)
            gateway.forward_uplink(b"\x40\x01", radio)

        pull_packets = [packet for packet in transport.sent_packets if packet[3] == 0x02]
        self.assertEqual(len(pull_packets), 2)
        gateway.stop()
