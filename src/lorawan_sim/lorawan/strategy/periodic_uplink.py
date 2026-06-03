from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterator

from lorawan_sim.lorawan.device.model import SimulatedDevice


@dataclass
class PeriodicUplinkStrategy:
    interval_sec: int
    count: int
    payload: bytes
    f_port: int
    confirmed: bool

    def generate(self, device: SimulatedDevice) -> Iterator[bytes]:
        for _ in range(self.count):
            yield device.build_data_uplink(
                payload=self.payload,
                f_port=self.f_port,
                confirmed=self.confirmed,
            )
            time.sleep(self.interval_sec)
