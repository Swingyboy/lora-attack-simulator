from __future__ import annotations

import unittest

from lorawan_sim.domain.scenario.loader import load_scenario


class ScenarioLoaderTests(unittest.TestCase):
    def test_load_example_scenario(self) -> None:
        cfg = load_scenario("examples/debug-join-uplink.json")
        self.assertEqual(cfg.scenario.name, "debug-join-uplink")
        self.assertEqual(cfg.gateway.gateway_eui, "0102030405060708")
        self.assertEqual(cfg.device.activation.mode, "OTAA")
        self.assertEqual(cfg.uplink.count, 3)
