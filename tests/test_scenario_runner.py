from __future__ import annotations

import logging
import unittest
from dataclasses import dataclass
from unittest.mock import patch

from simulator.scenario_runner import ScenarioRunner
from lorawan.scenario.schema import (
    ActivationConfig,
    DeviceConfig,
    GatewayConfig,
    LoggingConfig,
    PayloadConfig,
    RadioMetadata,
    ScenarioConfig,
    ScenarioMeta,
    SemtechUdpConfig,
    UplinkConfig,
)


@dataclass
class _FakeRuntime:
    joined: bool = False
    dev_addr_hex: str = "26011bda"


class _FakeDevice:
    def __init__(self) -> None:
        self.runtime = _FakeRuntime()
        self.join_requests_sent = 0
        self.uplinks_sent = 0

    def build_join_request(self) -> bytes:
        self.join_requests_sent += 1
        return b"join"

    def apply_join_accept(self, phy_payload: bytes) -> None:
        self.runtime.joined = True

    def build_data_uplink(self, payload: bytes, f_port: int, confirmed: bool) -> bytes:
        self.uplinks_sent += 1
        return f"up{self.uplinks_sent}".encode("ascii")


class _FakeGateway:
    def __init__(self) -> None:
        self.started = False
        self.stopped = False
        self.join_accept_responses = [None, b"accept"]
        self.forwarded_packets: list[bytes] = []
        self.uplink_frames = 0

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def forward_uplink(self, phy_payload: bytes, radio: RadioMetadata) -> None:
        self.forwarded_packets.append(phy_payload)
        if phy_payload.startswith(b"up"):
            self.uplink_frames += 1
            if self.uplink_frames >= 3:
                raise KeyboardInterrupt()

    def await_downlink(self, timeout_sec: float) -> bytes | None:
        return self.join_accept_responses.pop(0)


class ScenarioRunnerTests(unittest.TestCase):
    def test_runner_retries_join_and_keeps_uplinking_until_manual_stop(self) -> None:
        gateway = _FakeGateway()
        device = _FakeDevice()
        runner = ScenarioRunner(
            logger=logging.getLogger("test"),
            gateway_factory=lambda cfg, logger: gateway,
            device_factory=lambda cfg: device,
        )
        config = ScenarioConfig(
            scenario=ScenarioMeta(name="test", description="test", duration_sec=1),
            gateway=GatewayConfig(
                gateway_eui="0102030405060708",
                semtech_udp=SemtechUdpConfig(host="127.0.0.1", port=1700, pull_data_interval_sec=1),
                radio_metadata=RadioMetadata(frequency=868100000, data_rate="SF7BW125", rssi=-60, snr=7.5),
            ),
            device=DeviceConfig(
                name="dev",
                lorawan_version="1.0.3",
                region="EU868",
                device_class="A",
                activation=ActivationConfig(
                    mode="OTAA",
                    dev_eui="0011223344556677",
                    join_eui="0102030405060708",
                    app_key="00112233445566778899aabbccddeeff",
                ),
            ),
            uplink=UplinkConfig(
                enabled=True,
                interval_sec=1,
                count=1,
                confirmed=False,
                f_port=10,
                payload=PayloadConfig(encoding="hex", value="010203"),
            ),
            logging=LoggingConfig(level="INFO", log_phy_payload=False, log_semtech_udp=False),
        )

        with patch("lorawan_sim.core.runner.scenario_runner.time.sleep", return_value=None):
            with self.assertRaises(KeyboardInterrupt):
                runner.run(config)

        self.assertTrue(gateway.started)
        self.assertTrue(gateway.stopped)
        self.assertEqual(device.join_requests_sent, 2)
        self.assertEqual(device.uplinks_sent, 3)

