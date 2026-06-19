"""Tests for strict configuration validation (P2 §1)."""

from __future__ import annotations

import pytest

from lora_attack_toolkit.config import (
    _expect_bool,
    _expect_enum,
    _expect_float,
    _expect_hex,
    _expect_int,
    parse_join_devnonce_config,
    parse_replay_config,
    parse_uplink_forgery_config,
)


# ── Primitive validators ──────────────────────────────────────────────────────


class TestExpectInt:
    def test_accepts_valid_int(self) -> None:
        assert _expect_int("x", 5) == 5

    def test_rejects_bool_true(self) -> None:
        with pytest.raises(ValueError, match="must be integer"):
            _expect_int("x", True)

    def test_rejects_bool_false(self) -> None:
        with pytest.raises(ValueError, match="must be integer"):
            _expect_int("x", False)

    def test_rejects_string(self) -> None:
        with pytest.raises(ValueError, match="must be integer"):
            _expect_int("x", "5")

    def test_rejects_float(self) -> None:
        with pytest.raises(ValueError, match="must be integer"):
            _expect_int("x", 5.0)

    def test_rejects_none(self) -> None:
        with pytest.raises(ValueError, match="must be integer"):
            _expect_int("x", None)

    def test_min_value_boundary_ok(self) -> None:
        assert _expect_int("x", 0, min_value=0) == 0

    def test_min_value_violation(self) -> None:
        with pytest.raises(ValueError, match=">= 1"):
            _expect_int("x", 0, min_value=1)

    def test_max_value_boundary_ok(self) -> None:
        assert _expect_int("x", 10, max_value=10) == 10

    def test_max_value_violation(self) -> None:
        with pytest.raises(ValueError, match="<= 5"):
            _expect_int("x", 6, max_value=5)

    def test_error_message_includes_name(self) -> None:
        with pytest.raises(ValueError, match="replay_count"):
            _expect_int("replay_count", "bad")


class TestExpectFloat:
    def test_accepts_int_as_float(self) -> None:
        assert _expect_float("x", 5) == 5.0

    def test_accepts_float(self) -> None:
        assert _expect_float("x", 3.14) == pytest.approx(3.14)

    def test_rejects_bool(self) -> None:
        with pytest.raises(ValueError, match="must be a number"):
            _expect_float("x", True)

    def test_rejects_string(self) -> None:
        with pytest.raises(ValueError, match="must be a number"):
            _expect_float("x", "3.14")

    def test_min_value_violation(self) -> None:
        with pytest.raises(ValueError, match=">= 0.0"):
            _expect_float("x", -1.0, min_value=0.0)


class TestExpectBool:
    def test_accepts_true(self) -> None:
        assert _expect_bool("x", True) is True

    def test_accepts_false(self) -> None:
        assert _expect_bool("x", False) is False

    def test_rejects_int_1(self) -> None:
        with pytest.raises(ValueError, match="must be boolean"):
            _expect_bool("x", 1)

    def test_rejects_int_0(self) -> None:
        with pytest.raises(ValueError, match="must be boolean"):
            _expect_bool("x", 0)

    def test_rejects_string(self) -> None:
        with pytest.raises(ValueError, match="must be boolean"):
            _expect_bool("x", "true")

    def test_rejects_none(self) -> None:
        with pytest.raises(ValueError, match="must be boolean"):
            _expect_bool("x", None)


class TestExpectEnum:
    _OPTS = {"alpha", "beta", "gamma"}

    def test_accepts_valid(self) -> None:
        assert _expect_enum("x", "alpha", self._OPTS) == "alpha"

    def test_rejects_unknown(self) -> None:
        with pytest.raises(ValueError, match="must be one of"):
            _expect_enum("x", "delta", self._OPTS)

    def test_rejects_int(self) -> None:
        with pytest.raises(ValueError, match="must be a string"):
            _expect_enum("x", 1, self._OPTS)  # type: ignore[arg-type]

    def test_error_includes_allowed(self) -> None:
        with pytest.raises(ValueError, match="alpha"):
            _expect_enum("mode", "bad", self._OPTS)


class TestExpectHex:
    def test_accepts_valid(self) -> None:
        assert _expect_hex("key", "DEADBEEF", 4) == "DEADBEEF"

    def test_rejects_wrong_length(self) -> None:
        with pytest.raises(ValueError, match="8 hex chars"):
            _expect_hex("key", "DEAD", 4)

    def test_rejects_invalid_chars(self) -> None:
        with pytest.raises(ValueError, match="valid hex"):
            _expect_hex("key", "XXXXXX00", 4)

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ValueError, match="must be a hex string"):
            _expect_hex("key", 12345678, 4)  # type: ignore[arg-type]


# ── Parser-level strict validation ────────────────────────────────────────────


class TestParseReplayConfig:
    def test_valid_flat_config(self) -> None:
        cfg = parse_replay_config(
            {
                "uplink_interval_sec": 30.0,
                "capture_fcnt": 5,
                "replay_attempt_interval_sec": 5.0,
                "replay_count": 3,
                "verification_uplink_count": 5,
                "device_time_gps_tolerance_sec": 2.0,
            }
        )
        assert cfg.replay_count == 3  # type: ignore[union-attr]

    def test_rejects_bool_as_replay_count(self) -> None:
        with pytest.raises(ValueError, match="replay_count.*must be integer"):
            parse_replay_config(
                {
                    "uplink_interval_sec": 30.0,
                    "capture_fcnt": 5,
                    "replay_attempt_interval_sec": 5.0,
                    "replay_count": True,  # bool masquerading as int
                }
            )

    def test_rejects_negative_uplink_interval(self) -> None:
        with pytest.raises(ValueError, match="uplink_interval_sec.*>= 0"):
            parse_replay_config(
                {
                    "uplink_interval_sec": -1.0,
                    "capture_fcnt": 5,
                    "replay_attempt_interval_sec": 5.0,
                }
            )

    def test_rejects_zero_replay_count(self) -> None:
        with pytest.raises(ValueError, match="replay_count.*>= 1"):
            parse_replay_config(
                {
                    "uplink_interval_sec": 30.0,
                    "capture_fcnt": 5,
                    "replay_attempt_interval_sec": 5.0,
                    "replay_count": 0,
                }
            )


class TestParseUplinkForgeryConfig:
    def test_valid_config(self) -> None:
        cfg = parse_uplink_forgery_config(
            {
                "forgery_mode": "invalid_mic",
                "perform_join": True,
                "corrupt_mic": True,
                "recalculate_mic": False,
                "fport": 10,
            }
        )
        assert cfg.forgery_mode == "invalid_mic"

    def test_rejects_unknown_forgery_mode(self) -> None:
        with pytest.raises(ValueError, match="Unknown forgery_mode"):
            parse_uplink_forgery_config({"forgery_mode": "nuclear_option"})

    def test_rejects_bool_as_fport(self) -> None:
        with pytest.raises(ValueError, match="fport.*must be integer"):
            parse_uplink_forgery_config(
                {
                    "forgery_mode": "invalid_mic",
                    "fport": True,
                }
            )

    def test_rejects_fport_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="fport.*<= 223"):
            parse_uplink_forgery_config(
                {
                    "forgery_mode": "invalid_mic",
                    "fport": 250,
                }
            )

    def test_rejects_recalculate_and_corrupt_mic_conflict(self) -> None:
        with pytest.raises(ValueError, match="cannot both be true"):
            parse_uplink_forgery_config(
                {
                    "forgery_mode": "invalid_mic",
                    "recalculate_mic": True,
                    "corrupt_mic": True,
                }
            )

    def test_rejects_perform_join_as_int(self) -> None:
        with pytest.raises(ValueError, match="perform_join.*must be boolean"):
            parse_uplink_forgery_config(
                {
                    "forgery_mode": "invalid_mic",
                    "perform_join": 1,
                }
            )

    def test_rejects_negative_fcnt_delta(self) -> None:
        with pytest.raises(ValueError, match="fcnt_delta.*>= 1"):
            parse_uplink_forgery_config(
                {
                    "forgery_mode": "fcnt_jump_forward",
                    "fcnt_delta": 0,
                }
            )


class TestParseJoinDevNonceConfig:
    def test_valid_minimal(self) -> None:
        cfg = parse_join_devnonce_config({})
        assert cfg.valid_join_count >= 1

    def test_rejects_bool_as_valid_join_count(self) -> None:
        with pytest.raises(ValueError, match="valid_join_count.*must be integer"):
            parse_join_devnonce_config({"valid_join_count": True})

    def test_rejects_zero_valid_join_count(self) -> None:
        with pytest.raises(ValueError, match=">= 1"):
            parse_join_devnonce_config({"valid_join_count": 0})

    def test_rejects_bool_as_valid_devnonce_wrap(self) -> None:
        # valid_devnonce_wrap requires a JSON boolean
        with pytest.raises(ValueError, match="valid_devnonce_wrap.*must be boolean"):
            parse_join_devnonce_config({"valid_devnonce_wrap": 1})

    def test_accepts_random_devnonce_start(self) -> None:
        cfg = parse_join_devnonce_config({"valid_devnonce_start": "random"})
        assert cfg.valid_devnonce_start == "random"

    def test_rejects_invalid_devnonce_start_string(self) -> None:
        with pytest.raises(ValueError, match="'random'"):
            parse_join_devnonce_config({"valid_devnonce_start": "auto"})
