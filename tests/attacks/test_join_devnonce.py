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
                    "rx1_delay_sec": 5.0,
                    "rx1_window_sec": 1.0,
                    "rx2_delay_sec": 6.0,
                    "rx2_window_sec": 1.0,
                },
            }
        )

        self.assertIsInstance(config, JoinDevNonceConfigV1)
        self.assertEqual(config.valid_join_count, 50)
        self.assertEqual(config.valid_devnonce_start, 0)
        self.assertEqual(config.final_check, "replay_first")
        self.assertEqual(config.result_cache_size, 10)
        self.assertIsNotNone(config.timing)
        self.assertEqual(config.timing.rx1_window_sec, 1.0)
        self.assertEqual(config.timing.rx2_window_sec, 1.0)

    def test_rejects_short_join_accept_timeout(self) -> None:
        with self.assertRaises(ValueError):
            parse_join_devnonce_config(
                {
                    "valid_join_count": 1,
                    "final_check": "same_as_last",
                    "timing": {
                        "join_accept_timeout_sec": 6.0,
                        "rx1_delay_sec": 5.0,
                        "rx1_window_sec": 1.0,
                        "rx2_delay_sec": 6.0,
                        "rx2_window_sec": 1.0,
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
                    "rx1_delay_sec": 5.0,
                    "rx1_window_sec": 1.0,
                    "rx2_delay_sec": 6.0,
                    "rx2_window_sec": 1.0,
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
                timeout_sec=30.0,
            ),
        )

    def test_select_final_devnonce(self) -> None:
        attack = JoinDevNonceAttack()
        cache = DevNonceResultCache(max_size=3)
        cache.store(_step(b"\x01\x00", accepted=True, ts=1.0))
        cache.store(_step(b"\x02\x00", accepted=True, ts=2.0))

        same_as_last = attack._select_final_devnonce(
            replace(self.config, final_check="same_as_last"),
            cache,
        )
        replay_first = attack._select_final_devnonce(
            replace(self.config, final_check="replay_first"),
            cache,
        )
        lower_than_last = attack._select_final_devnonce(
            replace(self.config, final_check="lower_than_last"),
            cache,
        )

        self.assertEqual(same_as_last, b"\x02\x00")
        self.assertEqual(replay_first, b"\x01\x00")
        self.assertEqual(lower_than_last, b"\x01\x00")

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

        times = chain([0.0, 0.0, 5.0, 5.0, 5.0, 6.0, 6.0, 6.0, 6.5], repeat(6.5))

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


if __name__ == "__main__":
    unittest.main()
