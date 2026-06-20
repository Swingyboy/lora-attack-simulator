from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pytest

from lora_attack_toolkit.config import load_attack_scenario

pytestmark = pytest.mark.unit

_EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "attacks" / "uplink-replay-v1.json"


class ScenarioLoaderTests(unittest.TestCase):
    def test_scenario_loader_exists(self) -> None:
        # Basic test to ensure the loader module is importable
        # Note: All current examples are attack scenarios, not pure simulation scenarios
        # Attack scenarios are tested in test_attack_scenario_loader.py
        self.assertIsNotNone(load_attack_scenario)


class FrozenScopeValidationTests(unittest.TestCase):
    """Scenarios outside the frozen scope (EU868 / A / OTAA / 1.0.3) are rejected."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)

    def _load_mutated(self, mutate) -> None:
        data = json.loads(_EXAMPLE.read_text())
        mutate(data)
        tmp = Path(self._tmpdir.name) / "scenario.json"
        tmp.write_text(json.dumps(data))
        load_attack_scenario(str(tmp))

    def test_unsupported_region_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._load_mutated(lambda d: d["device"].__setitem__("region", "US915"))
        self.assertIn("device.region", str(ctx.exception))
        self.assertIn("US915", str(ctx.exception))

    def test_unsupported_device_class_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._load_mutated(lambda d: d["device"].__setitem__("class", "C"))
        self.assertIn("device.class", str(ctx.exception))

    def test_unsupported_activation_mode_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._load_mutated(lambda d: d["device"]["activation"].__setitem__("mode", "ABP"))
        self.assertIn("device.activation.mode", str(ctx.exception))

    def test_unsupported_lorawan_version_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._load_mutated(lambda d: d["device"].__setitem__("lorawan_version", "1.1.0"))
        self.assertIn("device.lorawan_version", str(ctx.exception))

    def test_supported_scope_loads(self) -> None:
        # The unmodified example is within scope and must load.
        scenario = load_attack_scenario(str(_EXAMPLE))
        self.assertEqual(scenario.device.region, "EU868")
        self.assertEqual(scenario.device.lorawan_version, "1.0.3")

    def test_duty_cycle_enforcement_disabled_by_default(self) -> None:
        # Item 3: duty-cycle enforcement is disabled by default in the diploma
        # scope; the production radio must not block on it.
        from lora_attack_toolkit.lorawan.radio import Radio
        from lora_attack_toolkit.runtime.device import create_device

        scenario = load_attack_scenario(str(_EXAMPLE))
        self.assertFalse(scenario.device.duty_cycle_enforcement)
        device = create_device(scenario.device)
        self.assertIsInstance(device.runtime.radio, Radio)
        assert device.runtime.radio is not None
        self.assertFalse(device.runtime.radio.supports_duty_cycle())

    def test_unknown_top_level_field_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._load_mutated(lambda d: d.__setitem__("bogus", 1))
        self.assertIn("bogus", str(ctx.exception))

    def test_unknown_device_field_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._load_mutated(lambda d: d["device"].__setitem__("frobnicate", True))
        self.assertIn("device.frobnicate", str(ctx.exception))

    def test_unknown_target_field_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._load_mutated(lambda d: d["target"].__setitem__("scheme", "tcp"))
        self.assertIn("target.scheme", str(ctx.exception))


class BundledScenarioTests(unittest.TestCase):
    """Every bundled example scenario must load under strict validation."""

    def test_all_examples_load(self) -> None:
        examples_dir = Path(__file__).resolve().parents[1] / "examples" / "attacks"
        files = sorted(examples_dir.glob("*.json"))
        self.assertTrue(files, "no bundled example scenarios found")
        for path in files:
            with self.subTest(scenario=path.name):
                scenario = load_attack_scenario(str(path))
                self.assertEqual(scenario.device.region, "EU868")
                self.assertEqual(scenario.target.transport, "semtech_udp")
