from __future__ import annotations

import unittest

from lora_attack_toolkit.core.loader import load_attack_scenario


class ScenarioLoaderTests(unittest.TestCase):
    def test_scenario_loader_exists(self) -> None:
        # Basic test to ensure the loader module is importable
        # Note: All current examples are attack scenarios, not pure simulation scenarios
        # Attack scenarios are tested in test_attack_scenario_loader.py
        self.assertIsNotNone(load_attack_scenario)
