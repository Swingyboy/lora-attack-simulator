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


class OptionalExpectedSectionTests(unittest.TestCase):
    """The expected section is optional; when absent the profile is derived from the version."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        # Minimal valid scenario without an expected section.
        self._base = {
            "target": {
                "name": "test-ns",
                "transport": "semtech_udp",
                "host": "127.0.0.1",
                "port": 1700,
            },
            "gateway": {
                "gateway_eui": "0102030405060708",
                "pull_data_interval_sec": 5,
                "radio": {
                    "region": "EU868",
                    "frequency_hz": 868100000,
                    "data_rate": "SF7BW125",
                    "rssi": -60,
                    "snr": 7.5,
                },
            },
            "device": {
                "name": "test-device",
                "lorawan_version": "1.0.4",
                "region": "EU868",
                "class": "A",
                "activation": {
                    "mode": "OTAA",
                    "dev_eui": "0011223344556677",
                    "join_eui": "0011223344556677",
                    "app_key": "00112233445566770011223344556677",
                },
            },
            "attack": {
                "type": "join_devnonce",
                "config": {"valid_join_count": 1, "final_check": "same_as_last"},
            },
            "logging": {"level": "info", "log_phy_payload": False, "log_semtech_udp": False},
        }

    def _write_and_load(self, data: dict) -> object:
        import json

        tmp = Path(self._tmpdir.name) / "scenario.json"
        tmp.write_text(json.dumps(data))
        return load_attack_scenario(str(tmp))

    def test_expected_absent_derives_profile_from_version_1_0_4(self) -> None:
        scenario = self._write_and_load(self._base)
        self.assertEqual(scenario.expected.profile, "lorawan_1_0_4_devnonce_validation")

    def test_expected_absent_derives_profile_from_version_1_1(self) -> None:
        import copy

        data = copy.deepcopy(self._base)
        data["device"]["lorawan_version"] = "1.1"
        scenario = self._write_and_load(data)
        self.assertEqual(scenario.expected.profile, "lorawan_1_1_devnonce_validation")

    def test_expected_absent_derives_profile_from_version_1_0_3(self) -> None:
        import copy

        data = copy.deepcopy(self._base)
        data["device"]["lorawan_version"] = "1.0.3"
        scenario = self._write_and_load(data)
        self.assertEqual(scenario.expected.profile, "lorawan_1_0_3_devnonce_validation")

    def test_explicit_expected_profile_is_preserved(self) -> None:
        """An explicit expected.profile always wins, regardless of version."""
        import copy

        data = copy.deepcopy(self._base)
        data["expected"] = {"profile": "lorawan_1_0_3_devnonce_validation"}
        scenario = self._write_and_load(data)
        self.assertEqual(scenario.expected.profile, "lorawan_1_0_3_devnonce_validation")

    def test_provenance_receives_derived_profile(self) -> None:
        """scenario.expected.profile is a non-empty string in the derived case."""
        scenario = self._write_and_load(self._base)
        self.assertIsInstance(scenario.expected.profile, str)
        self.assertTrue(scenario.expected.profile)
