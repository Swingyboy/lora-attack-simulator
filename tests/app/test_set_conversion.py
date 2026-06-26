"""Tests for type-driven value conversion in the interactive console set command."""

from __future__ import annotations

import copy
import unittest

import pytest

from lora_attack_toolkit.app.console import LoRaWANConsole
from lora_attack_toolkit.app.params import ParamMeta

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEVNONCE_SCENARIO: dict = {
    "attack": {
        "config": {
            "valid_devnonce_start": 0,
            "valid_devnonce_step": 1,
            "valid_devnonce_wrap": False,
            "target_lorawan_1_0_4": False,
            "final_check": "same_as_last",
        }
    }
}


def _set(data: dict, path: str, value_str: str) -> None:
    """Call _set_nested_value on a LoRaWANConsole instance (no gateway/session needed)."""
    console = object.__new__(LoRaWANConsole)
    console._set_nested_value(data, path, value_str)


def _scenario_with_start(start) -> dict:
    """Return a fresh scenario dict with the given valid_devnonce_start value."""
    d = copy.deepcopy(_DEVNONCE_SCENARIO)
    d["attack"]["config"]["valid_devnonce_start"] = start
    return d


# ---------------------------------------------------------------------------
# valid_devnonce_start  (declared type: int|random)
# ---------------------------------------------------------------------------


class TestValidDevnonceStartConversion(unittest.TestCase):
    """set attack.config.valid_devnonce_start must always produce int or 'random',
    regardless of the previously stored value."""

    PATH = "attack.config.valid_devnonce_start"

    def test_int_when_stored_int(self) -> None:
        d = _scenario_with_start(0)
        _set(d, self.PATH, "500")
        self.assertEqual(d["attack"]["config"]["valid_devnonce_start"], 500)
        self.assertIsInstance(d["attack"]["config"]["valid_devnonce_start"], int)

    def test_int_when_stored_large_int(self) -> None:
        d = _scenario_with_start(500)
        _set(d, self.PATH, "500")
        self.assertEqual(d["attack"]["config"]["valid_devnonce_start"], 500)
        self.assertIsInstance(d["attack"]["config"]["valid_devnonce_start"], int)

    def test_int_when_stored_random_string(self) -> None:
        """Regression: previously stored 'random' caused the new int to be kept as a str."""
        d = _scenario_with_start("random")
        _set(d, self.PATH, "500")
        self.assertEqual(d["attack"]["config"]["valid_devnonce_start"], 500)
        self.assertIsInstance(d["attack"]["config"]["valid_devnonce_start"], int)

    def test_random_when_stored_int(self) -> None:
        d = _scenario_with_start(0)
        _set(d, self.PATH, "random")
        self.assertEqual(d["attack"]["config"]["valid_devnonce_start"], "random")

    def test_random_when_stored_large_int(self) -> None:
        d = _scenario_with_start(500)
        _set(d, self.PATH, "random")
        self.assertEqual(d["attack"]["config"]["valid_devnonce_start"], "random")

    def test_random_when_stored_random_string(self) -> None:
        d = _scenario_with_start("random")
        _set(d, self.PATH, "random")
        self.assertEqual(d["attack"]["config"]["valid_devnonce_start"], "random")

    def test_random_case_insensitive(self) -> None:
        d = _scenario_with_start(0)
        _set(d, self.PATH, "RANDOM")
        self.assertEqual(d["attack"]["config"]["valid_devnonce_start"], "random")

    def test_invalid_string_raises(self) -> None:
        d = _scenario_with_start(0)
        with self.assertRaises(ValueError):
            _set(d, self.PATH, "abc")

    def test_invalid_string_raises_when_stored_random(self) -> None:
        d = _scenario_with_start("random")
        with self.assertRaises(ValueError):
            _set(d, self.PATH, "abc")

    def test_hex_prefix_is_accepted(self) -> None:
        d = _scenario_with_start(0)
        _set(d, self.PATH, "0x1F")
        self.assertEqual(d["attack"]["config"]["valid_devnonce_start"], 31)


# ---------------------------------------------------------------------------
# bool fields  (target_lorawan_1_0_4, valid_devnonce_wrap)
# ---------------------------------------------------------------------------


class TestBoolConversion(unittest.TestCase):
    """bool fields must convert correctly regardless of stored value."""

    PATH_FLAG = "attack.config.target_lorawan_1_0_4"
    PATH_WRAP = "attack.config.valid_devnonce_wrap"

    def test_true_from_false(self) -> None:
        d = copy.deepcopy(_DEVNONCE_SCENARIO)
        _set(d, self.PATH_FLAG, "true")
        self.assertIs(d["attack"]["config"]["target_lorawan_1_0_4"], True)

    def test_false_from_true(self) -> None:
        d = copy.deepcopy(_DEVNONCE_SCENARIO)
        d["attack"]["config"]["target_lorawan_1_0_4"] = True
        _set(d, self.PATH_FLAG, "false")
        self.assertIs(d["attack"]["config"]["target_lorawan_1_0_4"], False)

    def test_true_variants(self) -> None:
        for val in ("true", "True", "TRUE", "yes", "1"):
            with self.subTest(val=val):
                d = copy.deepcopy(_DEVNONCE_SCENARIO)
                _set(d, self.PATH_FLAG, val)
                self.assertIs(d["attack"]["config"]["target_lorawan_1_0_4"], True)

    def test_false_variants(self) -> None:
        for val in ("false", "False", "FALSE", "no", "0"):
            with self.subTest(val=val):
                d = copy.deepcopy(_DEVNONCE_SCENARIO)
                d["attack"]["config"]["target_lorawan_1_0_4"] = True
                _set(d, self.PATH_FLAG, val)
                self.assertIs(d["attack"]["config"]["target_lorawan_1_0_4"], False)

    def test_invalid_bool_raises(self) -> None:
        d = copy.deepcopy(_DEVNONCE_SCENARIO)
        with self.assertRaises(ValueError):
            _set(d, self.PATH_FLAG, "maybe")

    def test_wrap_bool(self) -> None:
        d = copy.deepcopy(_DEVNONCE_SCENARIO)
        _set(d, self.PATH_WRAP, "true")
        self.assertIs(d["attack"]["config"]["valid_devnonce_wrap"], True)


# ---------------------------------------------------------------------------
# enum fields  (final_check)
# ---------------------------------------------------------------------------


class TestEnumConversion(unittest.TestCase):
    PATH = "attack.config.final_check"

    def test_valid_enum_value(self) -> None:
        d = copy.deepcopy(_DEVNONCE_SCENARIO)
        _set(d, self.PATH, "replay_first")
        self.assertEqual(d["attack"]["config"]["final_check"], "replay_first")

    def test_invalid_enum_value_raises(self) -> None:
        d = copy.deepcopy(_DEVNONCE_SCENARIO)
        with self.assertRaises(ValueError):
            _set(d, self.PATH, "not_a_valid_mode")


# ---------------------------------------------------------------------------
# _convert_value: none/null sentinel
# ---------------------------------------------------------------------------


class TestNullSentinel(unittest.TestCase):
    def _convert(self, value_str: str, original: object, path: str | None = None) -> object:
        console = object.__new__(LoRaWANConsole)
        return console._convert_value(value_str, original, path)

    def test_none_sentinel(self) -> None:
        self.assertIsNone(self._convert("none", 42))

    def test_null_sentinel(self) -> None:
        self.assertIsNone(self._convert("null", "something"))


# ---------------------------------------------------------------------------
# _convert_by_type: direct unit tests
# ---------------------------------------------------------------------------


class TestConvertByType(unittest.TestCase):
    def _call(self, value_str: str, type_str: str, allowed: list[str] | None = None) -> object:
        console = object.__new__(LoRaWANConsole)
        meta = ParamMeta(
            path="test.path",
            type_str=type_str,
            description="",
            default=None,
            allowed_values=allowed,
        )
        return console._convert_by_type(value_str, meta)

    def test_bool_true(self) -> None:
        self.assertIs(self._call("true", "bool"), True)

    def test_bool_false(self) -> None:
        self.assertIs(self._call("false", "bool"), False)

    def test_bool_invalid_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._call("maybe", "bool")

    def test_int(self) -> None:
        self.assertEqual(self._call("42", "int"), 42)

    def test_int_hex(self) -> None:
        self.assertEqual(self._call("0xFF", "int"), 255)

    def test_int_invalid_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._call("abc", "int")

    def test_int_or_random_int(self) -> None:
        self.assertEqual(self._call("100", "int|random"), 100)

    def test_int_or_random_sentinel(self) -> None:
        self.assertEqual(self._call("random", "int|random"), "random")

    def test_int_or_random_invalid_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._call("abc", "int|random")

    def test_float(self) -> None:
        self.assertAlmostEqual(self._call("3.14", "float"), 3.14)

    def test_float_invalid_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._call("xyz", "float")

    def test_enum_valid(self) -> None:
        self.assertEqual(self._call("foo", "enum", allowed=["foo", "bar"]), "foo")

    def test_enum_invalid_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._call("baz", "enum", allowed=["foo", "bar"])

    def test_str_passthrough(self) -> None:
        self.assertEqual(self._call("hello", "str"), "hello")


# ---------------------------------------------------------------------------
# _convert_by_inference: legacy fallback path
# ---------------------------------------------------------------------------


class TestConvertByInference(unittest.TestCase):
    def _call(self, value_str: str, original: object) -> object:
        console = object.__new__(LoRaWANConsole)
        return console._convert_by_inference(value_str, original)

    def test_int_stored_converts_to_int(self) -> None:
        self.assertEqual(self._call("7", 0), 7)

    def test_int_stored_with_sentinel_returns_str(self) -> None:
        self.assertEqual(self._call("random", 0), "random")

    def test_float_stored_converts(self) -> None:
        self.assertAlmostEqual(self._call("1.5", 0.0), 1.5)

    def test_bool_stored_converts(self) -> None:
        self.assertIs(self._call("true", False), True)

    def test_str_stored_passthrough(self) -> None:
        self.assertEqual(self._call("anything", "old"), "anything")


if __name__ == "__main__":
    unittest.main()
