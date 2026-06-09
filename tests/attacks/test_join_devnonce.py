"""Tests for the unified DevNonce validation attack."""

from __future__ import annotations

import unittest
from dataclasses import replace
from logging import getLogger
from itertools import chain, repeat
from unittest.mock import MagicMock, Mock, patch

from lora_attack_toolkit.attacks.builtin.join_devnonce import (
    DevNonceResultCache,
    JoinDevNonceAttack,
    JoinStepResult,
)
from lora_attack_toolkit.attacks.context import AttackContext, AttackInput, AttackServices
from lora_attack_toolkit.attacks.packet_capture import PacketCapture
from lora_attack_toolkit.attacks.registry import AttackRegistry
from lora_attack_toolkit.attacks.bootstrap import register_builtin_attacks
from lora_attack_toolkit.core.schema import RadioMetadata
from lora_attack_toolkit.core.schema_v1 import JoinDevNonceConfigV1, parse_join_devnonce_config
from lora_attack_toolkit.device.model import SimulatedDevice
from lora_attack_toolkit.gateway.model import GatewaySimulator


def _step(dev_nonce: bytes, *, accepted: bool, ts: float = 0.0) -> JoinStepResult:
    return JoinStepResult(dev_nonce=dev_nonce, join_accepted=accepted, timestamp=ts)


class TestJoinDevNonceConfigParser(unittest.TestCase):
    def test_parse_unified_config(self) -> None:
        config = parse_join_devnonce_config(
            {
                "valid_join_count": 50,
                "valid_devnonce_start": 0,
                "valid_devnonce_step": 1,
                "final_check": "replay_first",
                "result_cache_size": 10,
                "timing": {
                    "join_accept_timeout_sec": 7.0,
                },
            }
        )

        self.assertIsInstance(config, JoinDevNonceConfigV1)
        self.assertEqual(config.valid_join_count, 50)
        self.assertEqual(config.valid_devnonce_start, 0)
        self.assertEqual(config.final_check, "replay_first")
        self.assertEqual(config.result_cache_size, 10)
        self.assertIsNotNone(config.timing)
        self.assertEqual(config.timing.join_accept_timeout_sec, 7.0)
        # RX1/RX2 values are internal defaults, not user-configurable
        self.assertEqual(config.timing.rx1_window_sec, 1.0)
        self.assertEqual(config.timing.rx2_window_sec, 1.0)

    def test_rx1_rx2_params_are_silently_ignored(self) -> None:
        """rx1/rx2 params in timing dict must be silently ignored (not user-configurable)."""
        config = parse_join_devnonce_config(
            {
                "final_check": "same_as_last",
                "timing": {
                    "join_accept_timeout_sec": 7.0,
                    "rx1_delay_sec": 99.0,
                    "rx2_delay_sec": 99.0,
                },
            }
        )
        # The parser must ignore rx1/rx2 values and use internal defaults
        self.assertEqual(config.timing.rx1_delay_sec, 1.0)
        self.assertEqual(config.timing.rx2_delay_sec, 2.0)

    def test_rejects_short_join_accept_timeout(self) -> None:
        """join_accept_timeout_sec must be >= internal rx2_delay + rx2_window (= 3.0)."""
        with self.assertRaises(ValueError):
            parse_join_devnonce_config(
                {
                    "valid_join_count": 1,
                    "final_check": "same_as_last",
                    "timing": {
                        "join_accept_timeout_sec": 2.0,
                    },
                }
            )


class TestDevNonceResultCache(unittest.TestCase):
    def test_cache_is_bounded(self) -> None:
        cache = DevNonceResultCache(max_size=2)

        cache.store(_step(b"\x01\x00", accepted=True, ts=1.0))
        cache.store(_step(b"\x02\x00", accepted=False, ts=2.0))
        cache.store(_step(b"\x03\x00", accepted=True, ts=3.0))

        self.assertEqual(cache.attempt_count, 3)
        self.assertEqual(cache.accepted_count, 2)
        self.assertEqual(cache.first_accepted_devnonce, b"\x01\x00")
        self.assertEqual(cache.last_accepted_devnonce, b"\x03\x00")
        self.assertEqual(list(cache.recent_accepted_devnonces), [b"\x01\x00", b"\x03\x00"])

    def test_attempt_count_tracks_all_attempts(self) -> None:
        cache = DevNonceResultCache(max_size=5)
        cache.store(_step(b"\x01\x00", accepted=False))
        cache.store(_step(b"\x02\x00", accepted=False))
        cache.store(_step(b"\x03\x00", accepted=True))

        self.assertEqual(cache.attempt_count, 3)
        self.assertEqual(cache.accepted_count, 1)


class TestJoinDevNonceAttack(unittest.TestCase):
    def setUp(self) -> None:
        self.logger = getLogger("test")
        self.device = MagicMock(spec=SimulatedDevice)
        self.device._join_eui = bytes.fromhex("0011223344556677")
        self.device._dev_eui = bytes.fromhex("0011223344556677")
        self.device._app_key = bytes.fromhex("00112233445566770011223344556677")
        self.device.apply_join_accept = MagicMock()
        self.gateway = MagicMock(spec=GatewaySimulator)
        self.gateway.start = MagicMock()
        self.gateway.stop = MagicMock()
        self.capture = PacketCapture(self.logger)
        self.radio = RadioMetadata(
            frequency=868100000,
            data_rate="SF7BW125",
            rssi=-60,
            snr=7.5,
        )
        self.config = parse_join_devnonce_config(
            {
                "valid_join_count": 1,
                "valid_devnonce_start": 1,
                "valid_devnonce_step": 1,
                "final_check": "same_as_last",
                "result_cache_size": 10,
                "timing": {
                    "join_accept_timeout_sec": 7.0,
                },
            }
        )
        self.ctx = AttackContext(
            services=AttackServices(
                device=self.device,
                gateway=self.gateway,
                logger=self.logger,
                capture=self.capture,
                metrics=None,
            ),
            input=AttackInput(
                typed_config=self.config,
                expected_behavior=None,
                radio=self.radio,
                timeout_sec=0.0,  # No inter-message delay in unit tests
            ),
        )

    def test_select_final_devnonce(self) -> None:
        attack = JoinDevNonceAttack()
        cache = DevNonceResultCache(max_size=3)
        cache.store(_step(b"\x01\x00", accepted=True, ts=1.0))
        cache.store(_step(b"\x02\x00", accepted=True, ts=2.0))

        same_as_last, _ = attack._select_final_devnonce(
            replace(self.config, final_check="same_as_last"),
            cache,
        )
        replay_first, _ = attack._select_final_devnonce(
            replace(self.config, final_check="replay_first"),
            cache,
        )
        # last=2, candidate 1 already used, candidate 0 is unused
        lower_than_last, ltl_meta = attack._select_final_devnonce(
            replace(self.config, final_check="lower_than_last"),
            cache,
        )

        self.assertEqual(same_as_last, b"\x02\x00")
        self.assertEqual(replay_first, b"\x01\x00")
        self.assertEqual(lower_than_last, b"\x00\x00")
        self.assertEqual(ltl_meta["lower_than_last_candidate_search_attempts"], 2)

    def test_run_exact_replay_uses_last_devnonce(self) -> None:
        attack = JoinDevNonceAttack()

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x02\x00", accepted=True, ts=1.0))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(
            return_value=_step(b"\x02\x00", accepted=False, ts=2.0)
        )

        result = attack.run(self.ctx)

        self.assertTrue(result.success)
        final_call = attack._execute_join_step.call_args_list[-1]
        self.assertEqual(final_call.kwargs["dev_nonce"], b"\x02\x00")
        self.assertEqual(final_call.kwargs["phase"], "final")

    def test_run_lower_than_last_uses_lower_devnonce(self) -> None:
        attack = JoinDevNonceAttack()

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x0a\x00", accepted=True, ts=1.0))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(
            return_value=_step(b"\x09\x00", accepted=False, ts=2.0)
        )

        result = attack.run(
            replace(self.ctx, input=replace(self.ctx.input, typed_config=replace(self.config, final_check="lower_than_last")))
        )

        self.assertTrue(result.success)
        self.assertEqual(attack._execute_join_step.call_args_list[-1].kwargs["dev_nonce"], b"\x09\x00")

    def test_run_replay_first_uses_first_devnonce(self) -> None:
        attack = JoinDevNonceAttack()

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x01\x00", accepted=True, ts=1.0))
            cache.store(_step(b"\x02\x00", accepted=True, ts=2.0))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(
            return_value=_step(b"\x01\x00", accepted=False, ts=3.0)
        )

        result = attack.run(
            replace(self.ctx, input=replace(self.ctx.input, typed_config=replace(self.config, final_check="replay_first")))
        )

        self.assertTrue(result.success)
        self.assertEqual(attack._execute_join_step.call_args_list[-1].kwargs["dev_nonce"], b"\x01\x00")

    # --- Memory-depth scenario tests ---

    def test_partial_generation_executes_final_check(self) -> None:
        """Final check runs even when some baseline joins were not accepted."""
        attack = JoinDevNonceAttack()
        config = replace(
            self.config,
            valid_join_count=3,
            final_check="replay_first",
        )

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x01\x00", accepted=True))
            cache.store(_step(b"\x02\x00", accepted=False))  # one failure
            cache.store(_step(b"\x03\x00", accepted=True))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(
            return_value=_step(b"\x01\x00", accepted=False)
        )

        ctx = replace(self.ctx, input=replace(self.ctx.input, typed_config=config))
        result = attack.run(ctx)

        self.assertTrue(result.success)
        self.assertIn("partial", result.message)
        self.assertTrue(result.metrics["generation_partial"])
        self.assertFalse(result.metrics["generation_complete"])
        self.assertTrue(result.metrics["final_check_executed"])
        self.assertEqual(result.metrics["generation_attempt_count"], 3)
        self.assertEqual(result.metrics["accepted_generation_count"], 2)
        self.assertEqual(result.metrics["failed_generation_count"], 1)

    def test_no_generation_skips_final_check(self) -> None:
        """Final check is not executed when no baseline Join was accepted."""
        attack = JoinDevNonceAttack()
        config = replace(self.config, final_check="replay_first")

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x01\x00", accepted=False))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock()

        ctx = replace(self.ctx, input=replace(self.ctx.input, typed_config=config))
        result = attack.run(ctx)

        self.assertFalse(result.success)
        self.assertIn("not executed", result.message)
        self.assertFalse(result.metrics["final_check_executed"])
        # final join step should not have been called
        attack._execute_join_step.assert_not_called()

    def test_replay_first_uses_first_accepted_not_first_attempted(self) -> None:
        """replay_first uses first accepted DevNonce even if the first attempt failed."""
        attack = JoinDevNonceAttack()
        config = replace(self.config, valid_join_count=3, final_check="replay_first")

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x01\x00", accepted=False))  # first attempt fails
            cache.store(_step(b"\x02\x00", accepted=True))   # first accepted
            cache.store(_step(b"\x03\x00", accepted=True))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(
            return_value=_step(b"\x02\x00", accepted=False)
        )

        ctx = replace(self.ctx, input=replace(self.ctx.input, typed_config=config))
        attack.run(ctx)

        final_call = attack._execute_join_step.call_args_list[-1]
        self.assertEqual(final_call.kwargs["dev_nonce"], b"\x02\x00")

    def test_lower_than_last_with_zero_devnonce_skips_final_check(self) -> None:
        """lower_than_last is inconclusive when the last accepted DevNonce is 0."""
        attack = JoinDevNonceAttack()
        config = replace(self.config, final_check="lower_than_last")

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x00\x00", accepted=True))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock()

        ctx = replace(self.ctx, input=replace(self.ctx.input, typed_config=config))
        result = attack.run(ctx)

        self.assertFalse(result.success)
        self.assertIn("not executed", result.message)
        self.assertFalse(result.metrics["final_check_executed"])
        attack._execute_join_step.assert_not_called()

    def test_full_generation_success_metrics(self) -> None:
        """generation_complete is True when all baseline joins were accepted."""
        attack = JoinDevNonceAttack()
        config = replace(self.config, valid_join_count=2, final_check="same_as_last")

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x01\x00", accepted=True))
            cache.store(_step(b"\x02\x00", accepted=True))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(
            return_value=_step(b"\x02\x00", accepted=False)
        )

        ctx = replace(self.ctx, input=replace(self.ctx.input, typed_config=config))
        result = attack.run(ctx)

        self.assertTrue(result.metrics["generation_complete"])
        self.assertFalse(result.metrics["generation_partial"])
        self.assertTrue(result.metrics["final_check_executed"])
        self.assertNotIn("partial", result.message)

    def test_execute_join_step_sets_runtime_dev_nonce(self) -> None:
        """runtime.dev_nonce must be set before apply_join_accept is called."""
        from lora_attack_toolkit.device.model import DeviceRuntime

        attack = JoinDevNonceAttack()
        dev_nonce = b"\x05\x00"

        device = MagicMock(spec=SimulatedDevice)
        device._join_eui = self.device._join_eui
        device._dev_eui = self.device._dev_eui
        device._app_key = self.device._app_key
        device.runtime = DeviceRuntime()

        gateway = MagicMock(spec=GatewaySimulator)
        gateway.await_downlink.return_value = None  # no JoinAccept

        ctx = AttackContext(
            services=replace(self.ctx.services, device=device, gateway=gateway),
            input=self.ctx.input,
            state={},
        )

        # First few calls return 0 (so sleep is skipped), then large value so
        # all RX windows are immediately considered expired.
        times = chain([0.0, 0.0, 0.0], repeat(100.0))
        with patch("lora_attack_toolkit.attacks.builtin.join_devnonce.time.monotonic", side_effect=lambda: next(times)), \
             patch("lora_attack_toolkit.attacks.builtin.join_devnonce.time.sleep"):
            attack._execute_join_step(
                ctx=ctx,
                config=self.config,
                timing=self.config.timing,
                dev_nonce=dev_nonce,
                attempt_index=1,
                phase="generation",
            )

        self.assertEqual(device.runtime.dev_nonce, dev_nonce)

    def test_wait_for_join_accept_uses_configured_windows(self) -> None:
        attack = JoinDevNonceAttack()
        gateway = MagicMock()
        gateway.await_downlink.side_effect = [None, b"\x20\x00"]
        ctx = AttackContext(
            services=replace(self.ctx.services, gateway=gateway),
            input=self.ctx.input,
            state=dict(self.ctx.state),
        )

        # Time sequence matched to default RX windows:
        # rx1_delay=1.0, rx1_window=1.0, rx2_delay=2.0, rx2_window=1.0
        # start=0.0, _sleep_until(1.0): 0.0<1.0→sleep, remaining=1.0-1.0=0→break
        # RX1 inner while: 1.0<2.0→enter, remaining=2.0-1.0=1.0, await→None
        #   back: 2.0→not<2.0→exit
        # _sleep_until(2.0): 2.0→not<2.0→skip
        # RX2 inner while: 2.0<3.0→enter, remaining=3.0-2.0=1.0, await→accept
        times = chain([0.0, 0.0, 1.0, 1.0, 1.0, 2.0, 2.0, 2.0, 2.0], repeat(2.0))

        with patch("lora_attack_toolkit.attacks.builtin.join_devnonce.time.monotonic", side_effect=lambda: next(times)), patch(
            "lora_attack_toolkit.attacks.builtin.join_devnonce.time.sleep"
        ):
            accepted = attack._wait_for_join_accept(
                ctx=ctx,
                timing=self.config.timing,
                attempt_index=1,
                phase="generation",
                dev_nonce=b"\x01\x00",
            )

        self.assertTrue(accepted)
        self.assertGreaterEqual(gateway.await_downlink.call_count, 2)

    def test_old_join_attack_names_are_unsupported(self) -> None:
        AttackRegistry.clear()
        register_builtin_attacks()
        with self.assertRaises(ValueError):
            AttackRegistry.get_spec("join_replay")

        with self.assertRaises(ValueError):
            AttackRegistry.get_spec("join_flood")

        with self.assertRaises(ValueError):
            AttackRegistry.get_spec("join_abuse")


class TestDevNonceGeneration(unittest.TestCase):
    """Tests for randomized and deterministic DevNonce start and wrap behavior."""

    def setUp(self) -> None:
        self.attack = JoinDevNonceAttack()
        self.base_config = parse_join_devnonce_config(
            {
                "valid_join_count": 4,
                "valid_devnonce_start": 1,
                "valid_devnonce_step": 1,
                "final_check": "same_as_last",
                "result_cache_size": 10,
                "timing": {
                    "join_accept_timeout_sec": 3.0,
                },
            }
        )

    # --- Schema parsing ---

    def test_parse_numeric_start(self) -> None:
        cfg = parse_join_devnonce_config({"valid_devnonce_start": 100, "final_check": "same_as_last"})
        self.assertEqual(cfg.valid_devnonce_start, 100)

    def test_parse_random_start(self) -> None:
        cfg = parse_join_devnonce_config({"valid_devnonce_start": "random", "final_check": "same_as_last"})
        self.assertEqual(cfg.valid_devnonce_start, "random")

    def test_parse_invalid_string_start_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_join_devnonce_config({"valid_devnonce_start": "auto", "final_check": "same_as_last"})

    def test_parse_devnonce_seed(self) -> None:
        cfg = parse_join_devnonce_config({"devnonce_seed": 42, "final_check": "same_as_last"})
        self.assertEqual(cfg.devnonce_seed, 42)

    def test_parse_valid_devnonce_wrap(self) -> None:
        cfg = parse_join_devnonce_config({"valid_devnonce_wrap": True, "final_check": "same_as_last"})
        self.assertTrue(cfg.valid_devnonce_wrap)

    # --- Resolve start ---

    def test_resolve_numeric_start(self) -> None:
        cfg = replace(self.base_config, valid_devnonce_start=50)
        self.assertEqual(self.attack._resolve_devnonce_start(cfg), 50)

    def test_resolve_random_start_within_range(self) -> None:
        cfg = replace(self.base_config, valid_devnonce_start="random", devnonce_seed=None)
        value = self.attack._resolve_devnonce_start(cfg)
        self.assertGreaterEqual(value, 0)
        self.assertLessEqual(value, 0xFFFF)

    def test_resolve_random_start_with_seed_is_reproducible(self) -> None:
        cfg = replace(self.base_config, valid_devnonce_start="random", devnonce_seed=42)
        first = self.attack._resolve_devnonce_start(cfg)
        second = self.attack._resolve_devnonce_start(cfg)
        self.assertEqual(first, second)

    def test_resolve_random_start_different_seeds_differ(self) -> None:
        cfg_a = replace(self.base_config, valid_devnonce_start="random", devnonce_seed=1)
        cfg_b = replace(self.base_config, valid_devnonce_start="random", devnonce_seed=2)
        # Statistically near-certain that two distinct seeds produce different starts
        self.assertNotEqual(
            self.attack._resolve_devnonce_start(cfg_a),
            self.attack._resolve_devnonce_start(cfg_b),
        )

    # --- DevNonce generation sequence ---

    def test_generate_devnonce_numeric_start(self) -> None:
        cfg = replace(self.base_config, valid_devnonce_step=1)
        values = [
            int.from_bytes(self.attack._generate_devnonce(cfg, i, 10), "little")
            for i in range(4)
        ]
        self.assertEqual(values, [10, 11, 12, 13])

    def test_generate_devnonce_step(self) -> None:
        cfg = replace(self.base_config, valid_devnonce_step=5)
        values = [
            int.from_bytes(self.attack._generate_devnonce(cfg, i, 0), "little")
            for i in range(4)
        ]
        self.assertEqual(values, [0, 5, 10, 15])

    def test_generate_devnonce_wrap_at_boundary(self) -> None:
        cfg = replace(self.base_config, valid_devnonce_step=1, valid_devnonce_wrap=True)
        # Start two below max; next two values should wrap to 0 and 1
        values = [
            int.from_bytes(self.attack._generate_devnonce(cfg, i, 0xFFFE), "little")
            for i in range(4)
        ]
        self.assertEqual(values, [0xFFFE, 0xFFFF, 0, 1])

    def test_generate_devnonce_overflow_without_wrap_raises(self) -> None:
        cfg = replace(self.base_config, valid_devnonce_step=1, valid_devnonce_wrap=False)
        with self.assertRaises(ValueError):
            self.attack._generate_devnonce(cfg, 1, 0xFFFF)

    # --- Metrics ---

    def test_metrics_include_resolved_start_and_wrap(self) -> None:
        attack = JoinDevNonceAttack()
        config = replace(
            self.base_config,
            valid_join_count=1,
            valid_devnonce_start=77,
            devnonce_seed=None,
            valid_devnonce_wrap=True,
            final_check="same_as_last",
        )

        def fake_generation(ctx, cfg, timing, cache):
            cache.store(_step(b"\x4d\x00", accepted=True))
            return 77  # resolved_start

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(return_value=_step(b"\x4d\x00", accepted=False))

        logger = getLogger("test")
        device = MagicMock(spec=SimulatedDevice)
        device._join_eui = bytes.fromhex("0011223344556677")
        device._dev_eui = bytes.fromhex("0011223344556677")
        device._app_key = bytes.fromhex("00112233445566770011223344556677")
        gateway = MagicMock(spec=GatewaySimulator)
        capture = PacketCapture(logger)
        radio = RadioMetadata(frequency=868100000, data_rate="SF7BW125", rssi=-60, snr=7.5)
        ctx = AttackContext(
            services=AttackServices(device=device, gateway=gateway, logger=logger, capture=capture, metrics=None),
            input=AttackInput(typed_config=config, expected_behavior=None, radio=radio, timeout_sec=30.0),
        )

        result = attack.run(ctx)

        self.assertIn("resolved_devnonce_start", result.metrics)
        self.assertEqual(result.metrics["resolved_devnonce_start"], 77)
        self.assertIn("valid_devnonce_wrap", result.metrics)
        self.assertTrue(result.metrics["valid_devnonce_wrap"])
        self.assertNotIn("devnonce_seed", result.metrics)  # seed is None → omitted

    def test_metrics_include_seed_when_provided(self) -> None:
        attack = JoinDevNonceAttack()
        config = replace(
            self.base_config,
            valid_join_count=1,
            valid_devnonce_start="random",
            devnonce_seed=42,
            final_check="same_as_last",
        )

        import random as _random
        expected_start = _random.Random(42).randint(0, 0xFFFF)

        def fake_generation(ctx, cfg, timing, cache):
            nonce = expected_start.to_bytes(2, "little")
            cache.store(_step(nonce, accepted=True))
            return expected_start

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(
            return_value=_step(expected_start.to_bytes(2, "little"), accepted=False)
        )

        logger = getLogger("test")
        device = MagicMock(spec=SimulatedDevice)
        device._join_eui = bytes.fromhex("0011223344556677")
        device._dev_eui = bytes.fromhex("0011223344556677")
        device._app_key = bytes.fromhex("00112233445566770011223344556677")
        gateway = MagicMock(spec=GatewaySimulator)
        capture = PacketCapture(logger)
        radio = RadioMetadata(frequency=868100000, data_rate="SF7BW125", rssi=-60, snr=7.5)
        ctx = AttackContext(
            services=AttackServices(device=device, gateway=gateway, logger=logger, capture=capture, metrics=None),
            input=AttackInput(typed_config=config, expected_behavior=None, radio=radio, timeout_sec=30.0),
        )

        result = attack.run(ctx)

        self.assertEqual(result.metrics["resolved_devnonce_start"], expected_start)
        self.assertEqual(result.metrics["devnonce_seed"], 42)



class TestLowerThanLastSelection(unittest.TestCase):
    """Tests for lower_than_last DevNonce selection logic."""

    def setUp(self) -> None:
        self.attack = JoinDevNonceAttack()
        self.config = parse_join_devnonce_config(
            {
                "valid_join_count": 5,
                "valid_devnonce_start": 10,
                "valid_devnonce_step": 2,
                "final_check": "lower_than_last",
                "result_cache_size": 10,
                "timing": {
                    "join_accept_timeout_sec": 3.0,
                    "rx1_delay_sec": 1.0,
                    "rx1_window_sec": 1.0,
                    "rx2_delay_sec": 2.0,
                    "rx2_window_sec": 1.0,
                },
            }
        )

    def _make_cache(self, *nonces: int) -> DevNonceResultCache:
        cache = DevNonceResultCache(max_size=20)
        for n in nonces:
            cache.store(_step(n.to_bytes(2, "little"), accepted=True))
        return cache

    def test_step2_finds_unused_lower_value(self) -> None:
        # Generation: 10, 12, 14, 16, 18 → last=18, candidate 17 unused
        cache = self._make_cache(10, 12, 14, 16, 18)
        devnonce, meta = self.attack._select_final_devnonce(self.config, cache)
        self.assertEqual(int.from_bytes(devnonce, "little"), 17)
        self.assertEqual(meta["lower_than_last_candidate_search_attempts"], 1)

    def test_step1_skips_used_candidates(self) -> None:
        # Generation: 5, 6 → last=6, candidate 5 used, candidate 4 unused
        config = replace(self.config, valid_devnonce_step=1)
        cache = self._make_cache(5, 6)
        devnonce, meta = self.attack._select_final_devnonce(config, cache)
        self.assertEqual(int.from_bytes(devnonce, "little"), 4)
        self.assertEqual(meta["lower_than_last_candidate_search_attempts"], 2)

    def test_single_candidate_unused(self) -> None:
        # Only last accepted is 5; candidate 4 is unused → 1 attempt
        cache = self._make_cache(5)
        devnonce, meta = self.attack._select_final_devnonce(self.config, cache)
        self.assertEqual(int.from_bytes(devnonce, "little"), 4)
        self.assertEqual(meta["lower_than_last_candidate_search_attempts"], 1)

    def test_final_devnonce_not_in_accepted_set(self) -> None:
        # Ensure chosen DevNonce is not in the accepted set
        cache = self._make_cache(10, 12, 14, 16, 18)
        devnonce, _ = self.attack._select_final_devnonce(self.config, cache)
        self.assertNotIn(devnonce, cache.all_accepted_devnonces)

    def test_continuous_sequence_from_zero_raises(self) -> None:
        # 0..4 used, last=4, candidates 3..0 all used → error
        cache = self._make_cache(0, 1, 2, 3, 4)
        with self.assertRaises(ValueError) as ctx:
            self.attack._select_final_devnonce(self.config, cache)
        self.assertIn("unused lower-than-last", str(ctx.exception))

    def test_last_devnonce_zero_raises(self) -> None:
        cache = self._make_cache(0)
        with self.assertRaises(ValueError) as ctx:
            self.attack._select_final_devnonce(self.config, cache)
        self.assertIn("lower DevNonce than 0", str(ctx.exception))

    def test_metrics_include_search_attempts(self) -> None:
        cache = self._make_cache(10, 12, 14, 16, 18)
        _, meta = self.attack._select_final_devnonce(self.config, cache)
        self.assertIn("lower_than_last_candidate_search_attempts", meta)

    def test_replay_first_unaffected(self) -> None:
        config = replace(self.config, final_check="replay_first")
        cache = self._make_cache(5, 7)
        devnonce, meta = self.attack._select_final_devnonce(config, cache)
        self.assertEqual(int.from_bytes(devnonce, "little"), 5)
        self.assertEqual(meta, {})

    def test_same_as_last_unaffected(self) -> None:
        config = replace(self.config, final_check="same_as_last")
        cache = self._make_cache(5, 7)
        devnonce, meta = self.attack._select_final_devnonce(config, cache)
        self.assertEqual(int.from_bytes(devnonce, "little"), 7)
        self.assertEqual(meta, {})

    def test_build_metrics_includes_final_devnonce_was_previously_used(self) -> None:
        attack = JoinDevNonceAttack()
        config = parse_join_devnonce_config({
            "valid_join_count": 2,
            "valid_devnonce_start": 10,
            "valid_devnonce_step": 2,
            "final_check": "lower_than_last",
            "timing": {
                "join_accept_timeout_sec": 3.0,
                "rx1_delay_sec": 1.0,
                "rx1_window_sec": 1.0,
                "rx2_delay_sec": 2.0,
                "rx2_window_sec": 1.0,
            },
        })

        def fake_generation(ctx, cfg, timing, cache):
            cache.store(_step(b"\x0a\x00", accepted=True))  # 10
            cache.store(_step(b"\x0c\x00", accepted=True))  # 12

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(
            return_value=_step(b"\x0b\x00", accepted=False)  # 11 (lower, unused)
        )

        logger = getLogger("test")
        device = MagicMock(spec=SimulatedDevice)
        gateway = MagicMock()
        capture = PacketCapture(logger=logger)
        radio = RadioMetadata(frequency=868100000, data_rate="SF7BW125", rssi=-60, snr=7.5)
        ctx = AttackContext(
            services=AttackServices(device=device, gateway=gateway, logger=logger, capture=capture, metrics=None),
            input=AttackInput(typed_config=config, expected_behavior=None, radio=radio, timeout_sec=30.0),
        )

        result = attack.run(ctx)
        self.assertIn("final_devnonce_was_previously_used", result.metrics)
        self.assertFalse(result.metrics["final_devnonce_was_previously_used"])
        self.assertEqual(result.metrics["final_devnonce_relation"], "lower_than_last")
        self.assertIn("lower_than_last_candidate_search_attempts", result.metrics)


if __name__ == "__main__":
    unittest.main()
