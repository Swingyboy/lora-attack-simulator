"""Tests for the unified DevNonce validation attack."""

from __future__ import annotations

import unittest
from dataclasses import replace
from logging import getLogger
from unittest.mock import MagicMock, Mock

import pytest

from lora_attack_toolkit.attacks.bootstrap import register_builtin_attacks
from lora_attack_toolkit.attacks.builtin.join_devnonce import (
    DevNonceResultCache,
    JoinDevNonceAttack,
    JoinStepResult,
)
from lora_attack_toolkit.attacks.context import AttackContext, AttackInput, AttackServices
from lora_attack_toolkit.attacks.packet_capture import PacketCapture
from lora_attack_toolkit.attacks.registry import AttackRegistry
from lora_attack_toolkit.config import (
    JoinDevNonceConfigV1,
    RadioMetadata,
    parse_join_devnonce_config,
)
from lora_attack_toolkit.lorawan.time_utils import FakeClock
from lora_attack_toolkit.runtime.device import DownlinkResult, SimulatedDevice
from lora_attack_toolkit.runtime.gateway import GatewaySimulator

pytestmark = pytest.mark.unit


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

    def test_deprecated_lorawan_1_0_4_monotonic_alias_normalized(self) -> None:
        """lorawan_1_0_4_monotonic_devnonce is normalized to lower_than_last (backward compat)."""
        config = parse_join_devnonce_config({"final_check": "lorawan_1_0_4_monotonic_devnonce"})
        self.assertEqual(config.final_check, "lower_than_last")

    def test_deprecated_alias_not_in_allowed_values(self) -> None:
        """lorawan_1_0_4_monotonic_devnonce must not appear in the final_check allowed_values."""
        from lora_attack_toolkit.app.params import get_allowed_values

        allowed = get_allowed_values("attack.config.final_check")
        self.assertIsNotNone(allowed)
        self.assertNotIn("lorawan_1_0_4_monotonic_devnonce", allowed)
        self.assertIn("lower_than_last", allowed)


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
        self.device.process_downlink = MagicMock(
            return_value=DownlinkResult(
                accepted=True,
                reject_reason=None,
                mtype=1,
                dev_addr_match=True,
                valid_mic=True,
                fcnt_ok=True,
                fcnt_32=-1,
                f_port=None,
                frm_payload=b"",
                mac_commands=[],
                applied_mac_commands=[],
                is_join_accept=True,
            )
        )
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
            clock=FakeClock(),
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
        attack._execute_join_step = Mock(return_value=_step(b"\x02\x00", accepted=False, ts=2.0))

        result = attack.run(self.ctx)

        self.assertTrue(result.success)
        final_call = next(
            c for c in attack._execute_join_step.call_args_list if c.kwargs["phase"] == "final"
        )
        self.assertEqual(final_call.kwargs["dev_nonce"], b"\x02\x00")
        self.assertEqual(final_call.kwargs["phase"], "final")

    def test_run_cancelled_after_generation_returns_cancelled(self) -> None:
        # When the cancel_event is set, the run must abort after the generation
        # phase and return a CANCELLED result without executing the final join.
        from lora_attack_toolkit.attacks.result import ExecutionStatus

        attack = JoinDevNonceAttack()

        def fake_generation(ctx, config, timing, cache):
            ctx.cancel_event.set()

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock()

        result = attack.run(self.ctx)

        self.assertEqual(result.execution_status, ExecutionStatus.CANCELLED)
        self.assertTrue(result.interrupted)
        attack._execute_join_step.assert_not_called()

    def test_run_lower_than_last_uses_lower_devnonce(self) -> None:
        attack = JoinDevNonceAttack()

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x0a\x00", accepted=True, ts=1.0))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(return_value=_step(b"\x09\x00", accepted=False, ts=2.0))

        result = attack.run(
            replace(
                self.ctx,
                input=replace(
                    self.ctx.input, typed_config=replace(self.config, final_check="lower_than_last")
                ),
            )
        )

        self.assertTrue(result.success)
        final_call = next(
            c for c in attack._execute_join_step.call_args_list if c.kwargs["phase"] == "final"
        )
        self.assertEqual(final_call.kwargs["dev_nonce"], b"\x09\x00")

    def test_run_replay_first_uses_first_devnonce(self) -> None:
        attack = JoinDevNonceAttack()

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x01\x00", accepted=True, ts=1.0))
            cache.store(_step(b"\x02\x00", accepted=True, ts=2.0))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(return_value=_step(b"\x01\x00", accepted=False, ts=3.0))

        result = attack.run(
            replace(
                self.ctx,
                input=replace(
                    self.ctx.input, typed_config=replace(self.config, final_check="replay_first")
                ),
            )
        )

        self.assertTrue(result.success)
        final_call = next(
            c for c in attack._execute_join_step.call_args_list if c.kwargs["phase"] == "final"
        )
        self.assertEqual(final_call.kwargs["dev_nonce"], b"\x01\x00")

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
        attack._execute_join_step = Mock(return_value=_step(b"\x01\x00", accepted=False))

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

        from lora_attack_toolkit.attacks.result import SecurityVerdict

        self.assertEqual(result.security_verdict, SecurityVerdict.INCONCLUSIVE)
        self.assertIn("not executed", result.message)
        self.assertFalse(result.metrics["final_check_executed"])
        # final join step should not have been called
        attack._execute_join_step.assert_not_called()

    def test_replay_first_uses_first_accepted_not_first_attempted(self) -> None:
        attack = JoinDevNonceAttack()
        config = replace(self.config, valid_join_count=3, final_check="replay_first")

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x01\x00", accepted=False))  # first attempt fails
            cache.store(_step(b"\x02\x00", accepted=True))  # first accepted
            cache.store(_step(b"\x03\x00", accepted=True))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(return_value=_step(b"\x02\x00", accepted=False))

        ctx = replace(self.ctx, input=replace(self.ctx.input, typed_config=config))
        attack.run(ctx)

        final_call = next(
            c for c in attack._execute_join_step.call_args_list if c.kwargs["phase"] == "final"
        )
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

        from lora_attack_toolkit.attacks.result import SecurityVerdict

        self.assertEqual(result.security_verdict, SecurityVerdict.INCONCLUSIVE)
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
        attack._execute_join_step = Mock(return_value=_step(b"\x02\x00", accepted=False))

        ctx = replace(self.ctx, input=replace(self.ctx.input, typed_config=config))
        result = attack.run(ctx)

        self.assertTrue(result.metrics["generation_complete"])
        self.assertFalse(result.metrics["generation_partial"])
        self.assertTrue(result.metrics["final_check_executed"])
        self.assertNotIn("partial", result.message)

    def test_rejected_final_with_control_ok_is_secure(self) -> None:
        """Tested DevNonce rejected but a fresh control join accepted → SECURE."""
        from lora_attack_toolkit.attacks.result import Confidence, SecurityVerdict

        attack = JoinDevNonceAttack()

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x02\x00", accepted=True, ts=1.0))

        def fake_step(ctx, config, timing, dev_nonce, attempt_index, phase):
            # final (replayed DevNonce) rejected; control (fresh DevNonce) accepted
            return _step(dev_nonce, accepted=(phase == "control"), ts=2.0)

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(side_effect=fake_step)

        result = attack.run(self.ctx)

        self.assertEqual(result.security_verdict, SecurityVerdict.SECURE)
        self.assertEqual(result.confidence, Confidence.HIGH)
        self.assertTrue(result.target_protected)
        self.assertTrue(result.metrics["control_probe_executed"])
        self.assertTrue(result.metrics["control_probe_accepted"])

    def test_rejected_final_with_control_silent_is_inconclusive(self) -> None:
        """Tested DevNonce and the control join both unanswered → INCONCLUSIVE."""
        from lora_attack_toolkit.attacks.result import Confidence, SecurityVerdict

        attack = JoinDevNonceAttack()

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x02\x00", accepted=True, ts=1.0))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        # Every join step (final + control) is unanswered → target may be down.
        attack._execute_join_step = Mock(
            side_effect=lambda **kw: _step(kw["dev_nonce"], accepted=False, ts=2.0)
        )

        result = attack.run(self.ctx)

        self.assertEqual(result.security_verdict, SecurityVerdict.INCONCLUSIVE)
        self.assertEqual(result.confidence, Confidence.LOW)
        self.assertIsNone(result.target_protected)
        self.assertTrue(result.metrics["control_probe_executed"])
        self.assertFalse(result.metrics["control_probe_accepted"])

    def test_accepted_final_is_vulnerable_without_control(self) -> None:
        """Tested DevNonce accepted → VULNERABLE; no control probe is sent."""
        from lora_attack_toolkit.attacks.result import SecurityVerdict

        attack = JoinDevNonceAttack()

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x02\x00", accepted=True, ts=1.0))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(
            side_effect=lambda **kw: _step(kw["dev_nonce"], accepted=True, ts=2.0)
        )

        result = attack.run(self.ctx)

        self.assertEqual(result.security_verdict, SecurityVerdict.VULNERABLE)
        self.assertFalse(result.target_protected)
        self.assertFalse(result.metrics["control_probe_executed"])
        # Only the final join step runs (no control phase).
        phases = [c.kwargs["phase"] for c in attack._execute_join_step.call_args_list]
        self.assertNotIn("control", phases)

    def test_monotonic_lower_rejected_control_ok_behavior_supported(self) -> None:
        """1.0.4 mode: lower DevNonce rejected + fresh control accepted → SECURE."""
        from lora_attack_toolkit.attacks.result import SecurityVerdict

        attack = JoinDevNonceAttack()

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x0a\x00", accepted=True, ts=1.0))

        def fake_step(ctx, config, timing, dev_nonce, attempt_index, phase):
            # lower DevNonce (final) rejected; fresh higher control accepted
            return _step(dev_nonce, accepted=(phase == "control"), ts=2.0)

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(side_effect=fake_step)

        ctx = replace(
            self.ctx,
            input=replace(
                self.ctx.input,
                typed_config=replace(self.config, final_check="lower_than_last"),
            ),
        )
        result = attack.run(ctx)

        self.assertEqual(result.security_verdict, SecurityVerdict.SECURE)
        self.assertTrue(result.target_protected)
        self.assertTrue(result.metrics["behavior_supported"])
        self.assertEqual(result.metrics["behavior_under_test"], "monotonic_devnonce")

    def test_monotonic_lower_accepted_unknown_profile_is_capability_only(self) -> None:
        """1.0.4 mode under unknown/1.0.3 profile: accepted lower DevNonce is not a vuln."""
        from lora_attack_toolkit.attacks.result import SecurityVerdict

        attack = JoinDevNonceAttack()

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x0a\x00", accepted=True, ts=1.0))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(
            side_effect=lambda **kw: _step(kw["dev_nonce"], accepted=True, ts=2.0)
        )

        ctx = replace(
            self.ctx,
            input=replace(
                self.ctx.input,
                typed_config=replace(self.config, final_check="lower_than_last"),
            ),
        )
        result = attack.run(ctx)

        self.assertEqual(result.security_verdict, SecurityVerdict.INCONCLUSIVE)
        self.assertFalse(result.metrics["behavior_supported"])

    def test_monotonic_lower_accepted_104_profile_is_vulnerable(self) -> None:
        """1.0.4 mode with target_lorawan_1_0_4=True: accepted lower DevNonce → VULNERABLE."""
        from lora_attack_toolkit.attacks.result import SecurityVerdict

        attack = JoinDevNonceAttack()

        def fake_generation(ctx, config, timing, cache):
            cache.store(_step(b"\x0a\x00", accepted=True, ts=1.0))

        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(
            side_effect=lambda **kw: _step(kw["dev_nonce"], accepted=True, ts=2.0)
        )

        ctx = replace(
            self.ctx,
            input=replace(
                self.ctx.input,
                typed_config=replace(
                    self.config,
                    final_check="lower_than_last",
                    target_lorawan_1_0_4=True,
                ),
            ),
        )
        result = attack.run(ctx)

        self.assertEqual(result.security_verdict, SecurityVerdict.VULNERABLE)
        self.assertFalse(result.target_protected)
        self.assertFalse(result.metrics["behavior_supported"])

    def test_control_devnonce_is_fresh(self) -> None:
        """The control probe must use a DevNonce not seen in generation or final."""
        attack = JoinDevNonceAttack()
        cache = DevNonceResultCache(max_size=10)
        cache.store(_step(b"\x00\x00", accepted=True))
        cache.store(_step(b"\x01\x00", accepted=True))
        final_devnonce = b"\x02\x00"
        control, reason = attack._select_control_devnonce(cache, final_devnonce)
        self.assertIsNotNone(control)
        self.assertNotIn(control, cache.all_accepted_devnonces)
        self.assertNotEqual(control, final_devnonce)
        self.assertEqual(reason, "")

    def test_control_devnonce_monotonic_above_last_accepted(self) -> None:
        """In monotonic mode the control DevNonce must be > last_accepted."""
        attack = JoinDevNonceAttack()
        cache = DevNonceResultCache(max_size=10)
        cache.store(_step(b"\x0a\x00", accepted=True))  # last_accepted = 10
        final_devnonce = b"\x09\x00"  # tested lower value
        control, reason = attack._select_control_devnonce(
            cache, final_devnonce, final_check="lower_than_last"
        )
        self.assertIsNotNone(control)
        self.assertGreater(int.from_bytes(control, "little"), 10)
        self.assertEqual(reason, "")

    def test_control_devnonce_monotonic_impossible_at_max(self) -> None:
        """Monotonic control probe is impossible when last_accepted == 0xFFFF."""
        attack = JoinDevNonceAttack()
        cache = DevNonceResultCache(max_size=10)
        cache.store(_step(b"\xff\xff", accepted=True))  # last_accepted = 65535
        final_devnonce = b"\xfe\xff"
        control, reason = attack._select_control_devnonce(
            cache, final_devnonce, final_check="lower_than_last"
        )
        self.assertIsNone(control)
        self.assertIn("impossible", reason)

    def test_control_devnonce_monotonic_impossible_returns_inconclusive(self) -> None:
        """Full run: INCONCLUSIVE with reason when control probe is impossible (last_accepted=0xFFFF)."""
        from lora_attack_toolkit.attacks.result import SecurityVerdict

        attack = JoinDevNonceAttack()
        config = replace(
            self.config,
            valid_join_count=1,
            valid_devnonce_start=0xFFFF,
            final_check="lower_than_last",
        )

        def fake_generation(ctx, config, timing, cache):
            # last_accepted = 0xFFFF; no valid control DevNonce can be > this
            cache.store(_step(b"\xff\xff", accepted=True, ts=1.0))
            return 0xFFFF

        # Final join (0xFFFE, lower than 0xFFFF) is rejected
        attack._execute_generation_phase = Mock(side_effect=fake_generation)
        attack._execute_join_step = Mock(
            side_effect=lambda **kw: _step(kw["dev_nonce"], accepted=False, ts=2.0)
        )

        ctx = replace(self.ctx, input=replace(self.ctx.input, typed_config=config))
        result = attack.run(ctx)

        self.assertEqual(result.security_verdict, SecurityVerdict.INCONCLUSIVE)
        self.assertIn("impossible", result.message)
        # Control probe must NOT have been executed
        self.assertFalse(result.metrics.get("control_probe_executed", True))

    def test_execute_join_step_sets_runtime_dev_nonce(self) -> None:
        """runtime.dev_nonce must be set before process_downlink is called."""
        from lora_attack_toolkit.runtime.device import DeviceRuntime

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
            clock=FakeClock(),
        )

        # With no JoinAccept the RX windows simply expire; the FakeClock advances
        # instantly so this is deterministic and fast.
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
            clock=FakeClock(),
        )

        # The FakeClock advances on every clock.sleep(), so the RX1 window opens,
        # yields one empty poll (None), then the RX2 poll returns the JoinAccept.
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
        cfg = parse_join_devnonce_config(
            {"valid_devnonce_start": 100, "final_check": "same_as_last"}
        )
        self.assertEqual(cfg.valid_devnonce_start, 100)

    def test_parse_random_start(self) -> None:
        cfg = parse_join_devnonce_config(
            {"valid_devnonce_start": "random", "final_check": "same_as_last"}
        )
        self.assertEqual(cfg.valid_devnonce_start, "random")

    def test_parse_invalid_string_start_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_join_devnonce_config(
                {"valid_devnonce_start": "auto", "final_check": "same_as_last"}
            )

    def test_parse_numeric_string_start(self) -> None:
        """A numeric string like '500' (produced by the set command) is accepted."""
        cfg = parse_join_devnonce_config(
            {"valid_devnonce_start": "500", "final_check": "same_as_last"}
        )
        self.assertEqual(cfg.valid_devnonce_start, 500)
        self.assertIsInstance(cfg.valid_devnonce_start, int)

    def test_parse_numeric_string_zero(self) -> None:
        cfg = parse_join_devnonce_config(
            {"valid_devnonce_start": "0", "final_check": "same_as_last"}
        )
        self.assertEqual(cfg.valid_devnonce_start, 0)

    def test_parse_random_string_case_insensitive(self) -> None:
        cfg = parse_join_devnonce_config(
            {"valid_devnonce_start": "RANDOM", "final_check": "same_as_last"}
        )
        self.assertEqual(cfg.valid_devnonce_start, "random")

    def test_parse_devnonce_seed(self) -> None:
        cfg = parse_join_devnonce_config({"devnonce_seed": 42, "final_check": "same_as_last"})
        self.assertEqual(cfg.devnonce_seed, 42)

    def test_parse_valid_devnonce_wrap(self) -> None:
        cfg = parse_join_devnonce_config(
            {"valid_devnonce_wrap": True, "final_check": "same_as_last"}
        )
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
            int.from_bytes(self.attack._generate_devnonce(cfg, i, 10), "little") for i in range(4)
        ]
        self.assertEqual(values, [10, 11, 12, 13])

    def test_generate_devnonce_step(self) -> None:
        cfg = replace(self.base_config, valid_devnonce_step=5)
        values = [
            int.from_bytes(self.attack._generate_devnonce(cfg, i, 0), "little") for i in range(4)
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
            services=AttackServices(
                device=device, gateway=gateway, logger=logger, capture=capture, metrics=None
            ),
            input=AttackInput(
                typed_config=config, expected_behavior=None, radio=radio, timeout_sec=30.0
            ),
            clock=FakeClock(),
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
            services=AttackServices(
                device=device, gateway=gateway, logger=logger, capture=capture, metrics=None
            ),
            input=AttackInput(
                typed_config=config, expected_behavior=None, radio=radio, timeout_sec=30.0
            ),
            clock=FakeClock(),
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
        config = parse_join_devnonce_config(
            {
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
            }
        )

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
            services=AttackServices(
                device=device, gateway=gateway, logger=logger, capture=capture, metrics=None
            ),
            input=AttackInput(
                typed_config=config, expected_behavior=None, radio=radio, timeout_sec=30.0
            ),
            clock=FakeClock(),
        )

        result = attack.run(ctx)
        self.assertIn("final_devnonce_was_previously_used", result.metrics)
        self.assertFalse(result.metrics["final_devnonce_was_previously_used"])
        self.assertEqual(result.metrics["final_devnonce_relation"], "lower_than_last")
        self.assertIn("lower_than_last_candidate_search_attempts", result.metrics)


class TestVersionDrivenConfig(unittest.TestCase):
    """Integration tests for version-driven target_lorawan_1_0_4 derivation."""

    _BASE_SCENARIO = {
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
            "lorawan_version": "1.0.3",
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
            "config": {
                "valid_join_count": 1,
                "final_check": "lower_than_last",
            },
        },
        "logging": {"level": "info", "log_phy_payload": False, "log_semtech_udp": False},
    }

    def _load_scenario(self, lorawan_version: str, extra_config: dict | None = None) -> object:
        import copy
        import json
        import tempfile
        from pathlib import Path

        from lora_attack_toolkit.config import load_attack_scenario

        data = copy.deepcopy(self._BASE_SCENARIO)
        data["device"]["lorawan_version"] = lorawan_version
        if extra_config:
            data["attack"]["config"].update(extra_config)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = Path(f.name)
        try:
            return load_attack_scenario(str(path))
        finally:
            path.unlink(missing_ok=True)

    def test_version_1_0_4_derives_target_lorawan_1_0_4_true(self) -> None:
        """lorawan_version=1.0.4 → typed config has target_lorawan_1_0_4=True."""
        from lora_attack_toolkit.config import parse_join_devnonce_config

        scenario = self._load_scenario("1.0.4")
        typed_config = parse_join_devnonce_config(scenario.attack.config)
        self.assertTrue(typed_config.target_lorawan_1_0_4)

    def test_version_1_1_derives_target_lorawan_1_0_4_true(self) -> None:
        """lorawan_version=1.1 → typed config has target_lorawan_1_0_4=True."""
        from lora_attack_toolkit.config import parse_join_devnonce_config

        scenario = self._load_scenario("1.1")
        typed_config = parse_join_devnonce_config(scenario.attack.config)
        self.assertTrue(typed_config.target_lorawan_1_0_4)

    def test_version_1_0_3_derives_target_lorawan_1_0_4_false(self) -> None:
        """lorawan_version=1.0.3 → typed config has target_lorawan_1_0_4=False."""
        from lora_attack_toolkit.config import parse_join_devnonce_config

        scenario = self._load_scenario("1.0.3")
        typed_config = parse_join_devnonce_config(scenario.attack.config)
        self.assertFalse(typed_config.target_lorawan_1_0_4)

    def test_version_wins_over_explicit_false_in_json(self) -> None:
        """device.lorawan_version always wins — explicit false in JSON is overridden."""
        from lora_attack_toolkit.config import parse_join_devnonce_config

        scenario = self._load_scenario("1.0.4", extra_config={"target_lorawan_1_0_4": False})
        typed_config = parse_join_devnonce_config(scenario.attack.config)
        self.assertTrue(typed_config.target_lorawan_1_0_4)

    def test_version_1_0_3_wins_over_explicit_true_in_json(self) -> None:
        """device.lorawan_version=1.0.3 always wins — explicit true in JSON is overridden."""
        from lora_attack_toolkit.config import parse_join_devnonce_config

        scenario = self._load_scenario("1.0.3", extra_config={"target_lorawan_1_0_4": True})
        typed_config = parse_join_devnonce_config(scenario.attack.config)
        self.assertFalse(typed_config.target_lorawan_1_0_4)

    def test_expected_section_absent_derives_profile_from_version(self) -> None:
        """When expected is omitted the profile is derived from lorawan_version."""
        scenario = self._load_scenario("1.0.4")
        self.assertEqual(scenario.expected.profile, "lorawan_1_0_4_devnonce_validation")

    def test_expected_section_absent_1_0_3_derives_profile(self) -> None:
        scenario = self._load_scenario("1.0.3")
        self.assertEqual(scenario.expected.profile, "lorawan_1_0_3_devnonce_validation")

    def test_explicit_profile_wins_over_derived(self) -> None:
        """An explicit expected.profile is preserved even when version would derive another."""
        import copy
        import json
        import tempfile
        from pathlib import Path

        from lora_attack_toolkit.config import load_attack_scenario

        data = copy.deepcopy(self._BASE_SCENARIO)
        data["device"]["lorawan_version"] = "1.0.4"
        data["expected"] = {"profile": "lorawan_1_0_3_devnonce_validation"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = Path(f.name)
        try:
            scenario = load_attack_scenario(str(path))
        finally:
            path.unlink(missing_ok=True)

        self.assertEqual(scenario.expected.profile, "lorawan_1_0_3_devnonce_validation")


if __name__ == "__main__":
    unittest.main()
