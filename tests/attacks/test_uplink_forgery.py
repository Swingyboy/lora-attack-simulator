"""Tests for the uplink forgery attack scenario.

Covers:
  1. Config parsing and schema validation
  2. Registry registration and CLI discovery
  3. Scenario loading (example file)
  4. Packet construction helpers
  5. Verdict logic
  6. End-to-end attack run (all modes, no network)
  7. Regression — join_replay and uplink_replay still pass
"""

from __future__ import annotations

import json
import unittest
from logging import getLogger
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from lora_attack_toolkit.attacks.builtin.uplink_forgery import (
    MAX_FCNT_GAP,
    ForgeryEvidence,
    ForgeryVerdict,
    UplinkForgeryAttack,
    _apply_mic_strategy,
    _build_mac_command_fopts,
    _forgery_verdict_to_security,
    corrupt_mic,
    determine_forgery_verdict,
)
from lora_attack_toolkit.attacks.context import AttackContext, AttackInput, AttackServices
from lora_attack_toolkit.attacks.packet_capture import PacketCapture
from lora_attack_toolkit.attacks.registry import AttackRegistry
from lora_attack_toolkit.attacks.result import ExecutionStatus
from lora_attack_toolkit.config import (
    UPLINK_FORGERY_MAC_COMMANDS,
    UPLINK_FORGERY_MODES,
    RadioMetadata,
    UplinkForgeryConfigV1,
    load_attack_scenario,
    parse_uplink_forgery_config,
)
from lora_attack_toolkit.lorawan.frames import build_unconfirmed_data_up
from lora_attack_toolkit.lorawan.time_utils import FakeClock

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.result import AttackResult

pytestmark = pytest.mark.unit

# ── Fixtures ──────────────────────────────────────────────────────────────────

_DEV_ADDR_LE = bytes.fromhex("04030201")  # DevAddr 01020304 stored LE
_NWK_S_KEY = bytes(16)
_APP_S_KEY = bytes(16)
_PAYLOAD = b"\xde\xad\xbe\xef"
_EXAMPLE_SCENARIO = Path("examples/attacks/uplink-forgery-v1.json")


def _radio() -> RadioMetadata:
    return RadioMetadata(frequency=868_100_000, data_rate="SF7BW125", rssi=-80, snr=7.0)


def _cfg(**kw) -> UplinkForgeryConfigV1:
    defaults = dict(
        forgery_mode="invalid_mic",
        perform_join=False,
        baseline_uplink_count=0,
        uplink_interval_sec=0.0,
        payload_hex="01020304",
        forged_payload_hex="DEADBEEF",
        fport=1,
        verification_uplink_count=0,
        corrupt_mic=True,
    )
    defaults.update(kw)
    return UplinkForgeryConfigV1(**defaults)


def _make_ctx(cfg: UplinkForgeryConfigV1) -> AttackContext:
    logger = getLogger("test")
    capture = PacketCapture(logger=logger)

    device = MagicMock()
    _fcnt = [0]

    def _build_uplink(payload, f_port, confirmed, f_opts=b""):
        frame = bytes([_fcnt[0] % 256]) + payload
        _fcnt[0] += 1
        device.runtime.fcnt_up = _fcnt[0]
        return frame

    device.runtime.fcnt_up = 0
    device.runtime.joined = True
    device.runtime.dev_addr_le = _DEV_ADDR_LE
    device.runtime.nwk_s_key = _NWK_S_KEY
    device.runtime.app_s_key = _APP_S_KEY
    device.runtime.radio = None
    device.build_data_uplink.side_effect = _build_uplink
    # select_uplink_radio delegates to the real method signature; mock it to
    # return the fallback radio unchanged (no Radio configured).
    device.select_uplink_radio.side_effect = lambda fcnt, fallback: fallback

    gateway = MagicMock()
    gateway.forward_uplink.return_value = None
    gateway.await_downlink.return_value = None
    gateway.await_downlink_structured.return_value = None

    services = AttackServices(device=device, gateway=gateway, logger=logger, capture=capture)
    inp = AttackInput(typed_config=cfg, expected_behavior=None, radio=_radio(), timeout_sec=30.0)
    return AttackContext(services=services, input=inp, clock=FakeClock())


# ── 1. Config parsing ─────────────────────────────────────────────────────────


class TestParseUplinkForgeryConfig(unittest.TestCase):
    def test_defaults(self) -> None:
        cfg = parse_uplink_forgery_config({})
        self.assertEqual(cfg.forgery_mode, "invalid_mic")
        self.assertTrue(cfg.perform_join)
        self.assertEqual(cfg.baseline_uplink_count, 5)
        self.assertAlmostEqual(cfg.uplink_interval_sec, 5.0)
        self.assertIsNone(cfg.target_fcnt)
        self.assertEqual(cfg.fcnt_delta, 10000)
        self.assertEqual(cfg.payload_hex, "01020304")
        self.assertEqual(cfg.forged_payload_hex, "DEADBEEF")
        self.assertFalse(cfg.recalculate_mic)
        self.assertTrue(cfg.corrupt_mic)
        self.assertEqual(cfg.wrong_devaddr, "26000000")
        self.assertEqual(cfg.mac_command, "DeviceTimeReq")
        self.assertEqual(cfg.fport, 1)
        self.assertEqual(cfg.verification_uplink_count, 3)

    def test_all_forgery_modes_accepted(self) -> None:
        for mode in UPLINK_FORGERY_MODES:
            cfg = parse_uplink_forgery_config({"forgery_mode": mode})
            self.assertEqual(cfg.forgery_mode, mode)

    def test_all_mac_commands_accepted(self) -> None:
        for cmd in UPLINK_FORGERY_MAC_COMMANDS:
            cfg = parse_uplink_forgery_config({"mac_command": cmd})
            self.assertEqual(cfg.mac_command, cmd)

    def test_unknown_mode_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_uplink_forgery_config({"forgery_mode": "nonexistent_mode"})

    def test_unknown_mac_command_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_uplink_forgery_config({"mac_command": "FakeCommand"})

    def test_explicit_values(self) -> None:
        raw = {
            "forgery_mode": "fcnt_jump_forward",
            "perform_join": False,
            "baseline_uplink_count": 3,
            "uplink_interval_sec": 1.0,
            "target_fcnt": 999,
            "fcnt_delta": 5000,
            "payload_hex": "CAFEBABE",
            "forged_payload_hex": "DEADBEEF",
            "recalculate_mic": True,
            "corrupt_mic": False,
            "wrong_devaddr": "01020304",
            "mac_command": "LinkCheckReq",
            "fport": 2,
            "verification_uplink_count": 2,
        }
        cfg = parse_uplink_forgery_config(raw)
        self.assertEqual(cfg.forgery_mode, "fcnt_jump_forward")
        self.assertFalse(cfg.perform_join)
        self.assertEqual(cfg.target_fcnt, 999)
        self.assertTrue(cfg.recalculate_mic)
        self.assertFalse(cfg.corrupt_mic)
        self.assertEqual(cfg.mac_command, "LinkCheckReq")


# ── 2. Registry registration ──────────────────────────────────────────────────


class TestUplinkForgeryRegistration(unittest.TestCase):
    def setUp(self) -> None:
        from lora_attack_toolkit.attacks.bootstrap import register_builtin_attacks

        register_builtin_attacks()

    def test_attack_registered(self) -> None:
        spec = AttackRegistry.get_spec("uplink_forgery")
        self.assertEqual(spec.name, "uplink_forgery")
        self.assertIs(spec.attack_class, UplinkForgeryAttack)

    def test_config_parser_registered(self) -> None:
        spec = AttackRegistry.get_spec("uplink_forgery")
        self.assertIs(spec.config_parser, parse_uplink_forgery_config)

    def test_cli_discovery(self) -> None:
        self.assertIn("uplink_forgery", AttackRegistry.list_attacks())

    def test_category(self) -> None:
        spec = AttackRegistry.get_spec("uplink_forgery")
        self.assertEqual(spec.category, "forgery")


# ── 3. Scenario loading ───────────────────────────────────────────────────────


class TestExampleScenarioLoading(unittest.TestCase):
    def test_example_file_exists(self) -> None:
        self.assertTrue(_EXAMPLE_SCENARIO.exists(), str(_EXAMPLE_SCENARIO))

    def test_example_json_valid(self) -> None:
        data = json.loads(_EXAMPLE_SCENARIO.read_text())
        self.assertEqual(data["attack"]["type"], "uplink_forgery")

    def test_example_all_forgery_modes_valid(self) -> None:
        data = json.loads(_EXAMPLE_SCENARIO.read_text())
        mode = data["attack"]["config"]["forgery_mode"]
        self.assertIn(mode, UPLINK_FORGERY_MODES)

    def test_scenario_loads_via_loader(self) -> None:
        scenario = load_attack_scenario(str(_EXAMPLE_SCENARIO))
        self.assertEqual(scenario.attack.type, "uplink_forgery")

    def test_console_discovers_scenario(self) -> None:
        """ScenarioMetadata.from_file must succeed for the example file."""
        from lora_attack_toolkit.app.console import ScenarioMetadata
        from lora_attack_toolkit.attacks.bootstrap import register_builtin_attacks

        register_builtin_attacks()
        meta = ScenarioMetadata.from_file(_EXAMPLE_SCENARIO)
        self.assertIsNotNone(meta)
        self.assertEqual(meta.scenario_type, "uplink_forgery")


# ── 4. Packet construction helpers ────────────────────────────────────────────


class TestCorruptMic(unittest.TestCase):
    def test_mic_is_bit_flipped(self) -> None:
        frame = b"\x40\x01\x02\x03\x04\xab\xcd\xef\x12"
        result = corrupt_mic(frame)
        self.assertEqual(result[:-4], frame[:-4])
        for orig, res in zip(frame[-4:], result[-4:]):
            self.assertEqual(res, orig ^ 0xFF)

    def test_short_frame_returned_unchanged(self) -> None:
        frame = b"\x01\x02\x03"
        self.assertEqual(corrupt_mic(frame), frame)


class TestApplyMicStrategy(unittest.TestCase):
    def _base_frame(self, fcnt: int = 1) -> bytes:
        return build_unconfirmed_data_up(
            dev_addr_le=_DEV_ADDR_LE,
            fcnt_up=fcnt,
            f_port=1,
            frm_payload=_PAYLOAD,
            app_s_key=_APP_S_KEY,
            nwk_s_key=_NWK_S_KEY,
            confirmed=False,
        )

    def test_recalculate_produces_valid_frame(self) -> None:
        base = self._base_frame(3)
        rebuilt, strategy = _apply_mic_strategy(
            frame=base,
            recalculate_mic=True,
            corrupt_mic_flag=False,
            dev_addr_le=_DEV_ADDR_LE,
            fcnt_up=3,
            fport=1,
            payload=_PAYLOAD,
            app_s_key=_APP_S_KEY,
            nwk_s_key=_NWK_S_KEY,
        )
        self.assertEqual(strategy, "recalculated")
        expected = build_unconfirmed_data_up(
            dev_addr_le=_DEV_ADDR_LE,
            fcnt_up=3,
            f_port=1,
            frm_payload=_PAYLOAD,
            app_s_key=_APP_S_KEY,
            nwk_s_key=_NWK_S_KEY,
            confirmed=False,
        )
        self.assertEqual(rebuilt, expected)

    def test_corrupt_flips_mic(self) -> None:
        base = self._base_frame(2)
        result, strategy = _apply_mic_strategy(
            frame=base,
            recalculate_mic=False,
            corrupt_mic_flag=True,
            dev_addr_le=_DEV_ADDR_LE,
            fcnt_up=2,
            fport=1,
            payload=_PAYLOAD,
            app_s_key=_APP_S_KEY,
            nwk_s_key=_NWK_S_KEY,
        )
        self.assertEqual(strategy, "corrupted")
        self.assertEqual(result[:-4], base[:-4])
        self.assertNotEqual(result[-4:], base[-4:])

    def test_no_strategy_keeps_original(self) -> None:
        base = self._base_frame(5)
        result, strategy = _apply_mic_strategy(
            frame=base,
            recalculate_mic=False,
            corrupt_mic_flag=False,
            dev_addr_le=_DEV_ADDR_LE,
            fcnt_up=5,
            fport=1,
            payload=_PAYLOAD,
            app_s_key=_APP_S_KEY,
            nwk_s_key=_NWK_S_KEY,
        )
        self.assertEqual(strategy, "original")
        self.assertEqual(result, base)

    def test_recalculate_takes_priority_over_corrupt(self) -> None:
        base = self._base_frame(7)
        result, strategy = _apply_mic_strategy(
            frame=base,
            recalculate_mic=True,
            corrupt_mic_flag=True,
            dev_addr_le=_DEV_ADDR_LE,
            fcnt_up=7,
            fport=1,
            payload=_PAYLOAD,
            app_s_key=_APP_S_KEY,
            nwk_s_key=_NWK_S_KEY,
        )
        self.assertEqual(strategy, "recalculated")


class TestBuildMacCommandFopts(unittest.TestCase):
    def test_all_commands_produce_nonempty_fopts(self) -> None:
        for cmd in UPLINK_FORGERY_MAC_COMMANDS:
            fopts = _build_mac_command_fopts(cmd)
            self.assertGreater(len(fopts), 0, f"empty fopts for {cmd}")

    def test_fopts_within_max_length(self) -> None:
        for cmd in UPLINK_FORGERY_MAC_COMMANDS:
            fopts = _build_mac_command_fopts(cmd)
            self.assertLessEqual(len(fopts), 15)


class TestFcntManipulation(unittest.TestCase):
    def _forge(self, mode: str, **kw) -> ForgeryEvidence:
        cfg = _cfg(forgery_mode=mode, **kw)
        ctx = _make_ctx(cfg)
        ctx.device.runtime.fcnt_up = 10
        attack = UplinkForgeryAttack()
        return attack._forge_and_transmit(
            ctx,
            cfg,
            {
                "dev_addr_le": _DEV_ADDR_LE,
                "dev_addr_hex": "01020304",
                "fcnt_up": 10,
                "nwk_s_key": _NWK_S_KEY,
                "app_s_key": _APP_S_KEY,
            },
        )

    def test_fcnt_jump_uses_delta(self) -> None:
        ev = self._forge("fcnt_jump_forward", fcnt_delta=9990)
        self.assertEqual(ev.fcnt_used, 10 + 9990)

    def test_fcnt_jump_uses_target_fcnt(self) -> None:
        ev = self._forge("fcnt_jump_forward", target_fcnt=42)
        self.assertEqual(ev.fcnt_used, 42)

    def test_fcnt_reuse_uses_previous_fcnt(self) -> None:
        ev = self._forge("fcnt_reuse_with_modified_payload")
        self.assertEqual(ev.fcnt_used, 9)

    def test_wrong_devaddr_uses_config_addr(self) -> None:
        ev = self._forge("wrong_devaddr", wrong_devaddr="01020304")
        self.assertEqual(ev.dev_addr_hex, "01020304")


class TestDeviceLayerUsed(unittest.TestCase):
    """Attack must call device.select_uplink_radio(), NOT any attacks/common helper."""

    def test_select_uplink_radio_called(self) -> None:
        cfg = _cfg(forgery_mode="invalid_mic")
        ctx = _make_ctx(cfg)
        UplinkForgeryAttack()._forge_and_transmit(
            ctx,
            cfg,
            {
                "dev_addr_le": _DEV_ADDR_LE,
                "dev_addr_hex": "01020304",
                "fcnt_up": 5,
                "nwk_s_key": _NWK_S_KEY,
                "app_s_key": _APP_S_KEY,
            },
        )
        ctx.device.select_uplink_radio.assert_called()


# ── 5. Verdict logic ──────────────────────────────────────────────────────────


class TestDetermineVerdict(unittest.TestCase):
    # Signature:
    #   determine_forgery_verdict(forgery_mode, mic_strategy,
    #                             attributable_accept, saw_unattributable, control_probe_ok)

    def test_attributable_validated_downlink_accepted(self) -> None:
        # invalid_mic forgery with an attributable validated downlink → ACCEPTED.
        self.assertEqual(
            determine_forgery_verdict("invalid_mic", "corrupted", True, False, False),
            ForgeryVerdict.ACCEPTED,
        )

    def test_unattributable_downlink_inconclusive(self) -> None:
        # A downlink was seen but could not be attributed → INCONCLUSIVE, not ACCEPTED.
        self.assertEqual(
            determine_forgery_verdict("invalid_mic", "corrupted", False, True, True),
            ForgeryVerdict.INCONCLUSIVE,
        )

    def test_no_downlink_control_ok_rejected(self) -> None:
        # No attributable downlink but control probe answered → meaningful REJECTED.
        self.assertEqual(
            determine_forgery_verdict("invalid_mic", "corrupted", False, False, True),
            ForgeryVerdict.REJECTED,
        )

    def test_no_downlink_control_failed_inconclusive(self) -> None:
        # No attributable downlink and control probe unanswered → INCONCLUSIVE.
        self.assertEqual(
            determine_forgery_verdict("invalid_mic", "corrupted", False, False, False),
            ForgeryVerdict.INCONCLUSIVE,
        )

    def test_valid_mic_always_accepted_expected(self) -> None:
        for attributable in (True, False):
            self.assertEqual(
                determine_forgery_verdict(
                    "valid_mic_modified_payload", "recalculated", attributable, False, False
                ),
                ForgeryVerdict.ACCEPTED_EXPECTED,
            )

    def test_fcnt_jump_attributable_accepted(self) -> None:
        self.assertEqual(
            determine_forgery_verdict("fcnt_jump_forward", "corrupted", True, False, False),
            ForgeryVerdict.ACCEPTED,
        )

    def test_fcnt_jump_no_evidence_control_ok_rejected(self) -> None:
        self.assertEqual(
            determine_forgery_verdict("fcnt_jump_forward", "corrupted", False, False, True),
            ForgeryVerdict.REJECTED,
        )

    def test_fcnt_reuse_no_evidence_control_ok_rejected(self) -> None:
        self.assertEqual(
            determine_forgery_verdict(
                "fcnt_reuse_with_modified_payload", "corrupted", False, False, True
            ),
            ForgeryVerdict.REJECTED,
        )

    def test_wrong_devaddr_no_evidence_control_ok_ignored(self) -> None:
        self.assertEqual(
            determine_forgery_verdict("wrong_devaddr", "wrong_devaddr_mic", False, False, True),
            ForgeryVerdict.IGNORED,
        )

    def test_wrong_devaddr_attributable_accepted(self) -> None:
        self.assertEqual(
            determine_forgery_verdict("wrong_devaddr", "wrong_devaddr_mic", True, False, False),
            ForgeryVerdict.ACCEPTED,
        )

    def test_mac_command_forgery_recalculated_attributable_expected(self) -> None:
        self.assertEqual(
            determine_forgery_verdict("mac_command_forgery", "recalculated", True, False, False),
            ForgeryVerdict.ACCEPTED_EXPECTED,
        )

    def test_mac_command_forgery_recalculated_no_evidence_inconclusive(self) -> None:
        self.assertEqual(
            determine_forgery_verdict("mac_command_forgery", "recalculated", False, False, True),
            ForgeryVerdict.INCONCLUSIVE,
        )

    def test_mac_command_forgery_corrupted_attributable_accepted(self) -> None:
        self.assertEqual(
            determine_forgery_verdict("mac_command_forgery", "corrupted", True, False, False),
            ForgeryVerdict.ACCEPTED,
        )

    def test_mac_command_forgery_corrupted_no_evidence_control_ok_rejected(self) -> None:
        self.assertEqual(
            determine_forgery_verdict("mac_command_forgery", "corrupted", False, False, True),
            ForgeryVerdict.REJECTED,
        )

    def test_unknown_mode_no_evidence_inconclusive(self) -> None:
        self.assertEqual(
            determine_forgery_verdict("unknown", "recalculated", False, False, False),
            ForgeryVerdict.INCONCLUSIVE,
        )

    def test_fcnt_jump_valid_mic_within_gap_not_vulnerable(self) -> None:
        # Valid-MIC forward jump below MAX_FCNT_GAP accepted → expected, not vulnerable.
        from lora_attack_toolkit.attacks.result import SecurityVerdict

        verdict = determine_forgery_verdict(
            "fcnt_jump_forward", "recalculated", True, False, False, fcnt_jump=MAX_FCNT_GAP - 1
        )
        self.assertEqual(verdict, ForgeryVerdict.ACCEPTED_EXPECTED)
        sv, _, _ = _forgery_verdict_to_security(verdict)
        self.assertNotEqual(sv, SecurityVerdict.VULNERABLE)

    def test_fcnt_jump_valid_mic_beyond_gap_policy_finding(self) -> None:
        # Valid-MIC forward jump at/beyond MAX_FCNT_GAP accepted → flagged policy finding,
        # but not auto-vulnerable (1.0.3 defines no explicit device-side rule).
        from lora_attack_toolkit.attacks.result import SecurityVerdict

        verdict = determine_forgery_verdict(
            "fcnt_jump_forward", "recalculated", True, False, False, fcnt_jump=MAX_FCNT_GAP + 5
        )
        self.assertEqual(verdict, ForgeryVerdict.POLICY_FINDING)
        sv, _, _ = _forgery_verdict_to_security(verdict)
        self.assertNotEqual(sv, SecurityVerdict.VULNERABLE)

    def test_fcnt_jump_valid_mic_unknown_jump_inconclusive(self) -> None:
        # Valid-MIC forward jump accepted but jump size unknown → INCONCLUSIVE.
        self.assertEqual(
            determine_forgery_verdict(
                "fcnt_jump_forward", "recalculated", True, False, False, fcnt_jump=None
            ),
            ForgeryVerdict.INCONCLUSIVE,
        )


# ── 6. End-to-end attack run ──────────────────────────────────────────────────


class TestUplinkForgeryAttackRun(unittest.TestCase):
    def _run_mode(self, mode: str, **kw) -> AttackResult:

        cfg = _cfg(forgery_mode=mode, **kw)
        ctx = _make_ctx(cfg)
        result = UplinkForgeryAttack().run(ctx)
        self.assertTrue(result.success, f"mode={mode}: {result.message}")
        self.assertEqual(result.attack_type, "uplink_forgery")
        return result

    def test_invalid_mic(self) -> None:
        r = self._run_mode("invalid_mic")
        self.assertEqual(r.metrics["mic_strategy"], "corrupted")

    def test_valid_mic_modified_payload(self) -> None:
        r = self._run_mode("valid_mic_modified_payload")
        self.assertEqual(r.metrics["mic_strategy"], "recalculated")
        self.assertEqual(r.metrics["verdict"], "accepted_expected")

    def test_fcnt_jump_forward(self) -> None:
        self._run_mode("fcnt_jump_forward")

    def test_fcnt_reuse(self) -> None:
        self._run_mode("fcnt_reuse_with_modified_payload")

    def test_wrong_devaddr(self) -> None:
        self._run_mode("wrong_devaddr")

    def test_mac_command_forgery_corrupted(self) -> None:
        r = self._run_mode("mac_command_forgery", corrupt_mic=True, recalculate_mic=False)
        self.assertEqual(r.metrics["mic_strategy"], "corrupted")

    def test_mac_command_forgery_valid_mic(self) -> None:
        r = self._run_mode("mac_command_forgery", recalculate_mic=True, corrupt_mic=False)
        self.assertEqual(r.metrics["mic_strategy"], "recalculated")

    def test_result_contains_all_evidence_fields(self) -> None:
        r = self._run_mode("invalid_mic")
        for key in (
            "forgery_mode",
            "dev_addr",
            "fcnt_used",
            "payload_hex",
            "mic_strategy",
            "frequency_hz",
            "data_rate",
            "tx_timestamp",
            "downlink_received",
            "downlink_count",
            "attributable_accept",
            "unattributable_downlink",
            "control_probe_ran",
            "control_probe_ok",
            "verification_accepted",
            "verdict",
            "verdict_label",
            "rationale",
        ):
            self.assertIn(key, r.metrics, f"Missing evidence field: {key}")

    def test_no_downlink_no_control_is_inconclusive(self) -> None:
        # Default fixture: gateway never returns a downlink, so the control probe
        # is unanswered → the verdict must be INCONCLUSIVE (never falsely secure).
        r = self._run_mode("invalid_mic")
        self.assertEqual(r.metrics["verdict"], "inconclusive")
        self.assertTrue(r.metrics["control_probe_ran"])
        self.assertFalse(r.metrics["control_probe_ok"])


# ── 6b. Attribution / control-probe wiring ────────────────────────────────────


class TestForgeryAttributionWiring(unittest.TestCase):
    def _ctx_with_downlinks(self, frames: list) -> object:
        from lora_attack_toolkit.runtime.gateway import ReceivedDownlink

        cfg = _cfg(forgery_mode="invalid_mic")
        ctx = _make_ctx(cfg)
        raw_seq = iter(frames)
        struct_seq = iter(frames)

        def _await(timeout_sec=0.0):
            try:
                return next(raw_seq)
            except StopIteration:
                return None

        def _await_structured(timeout_sec=0.0):
            try:
                frame = next(struct_seq)
            except StopIteration:
                return None
            return ReceivedDownlink(
                phy_payload=frame,
                token=b"\x12\x34",
                frequency_hz=869_525_000,
                data_rate="SF12BW125",
                concentrator_timestamp=42,
                received_monotonic=0.0,
            )

        ctx.gateway.await_downlink.side_effect = _await
        ctx.gateway.await_downlink_structured.side_effect = _await_structured
        return ctx

    def _evidence(self, ctx: object, tx_offset: float) -> ForgeryEvidence:
        return ForgeryEvidence(
            forgery_mode="invalid_mic",
            dev_addr_hex="01020304",
            fcnt_used=0,
            payload_hex="DEADBEEF",
            mic_strategy="corrupted",
            radio_frequency_hz=868_100_000,
            radio_data_rate="SF7BW125",
            tx_timestamp=ctx.clock.unix_time(),  # type: ignore[attr-defined]
            tx_monotonic=ctx.clock.monotonic() - tx_offset,  # type: ignore[attr-defined]
        )

    def test_validated_in_window_is_attributable(self) -> None:
        ctx = self._ctx_with_downlinks([b"\x60dl"])
        ctx.device.process_downlink.return_value = MagicMock(  # type: ignore[attr-defined]
            accepted=True, fcnt_32=3, reject_reason=None
        )
        evidence = self._evidence(ctx, tx_offset=1.0)  # rx_mono is 1.0s after tx → RX1 window
        total, attributable, unattributable = UplinkForgeryAttack()._drain_and_attribute(
            ctx,
            evidence,  # type: ignore[arg-type]
        )
        self.assertEqual((total, attributable, unattributable), (1, 1, 0))

    def test_validated_out_of_window_is_unattributable(self) -> None:
        ctx = self._ctx_with_downlinks([b"\x60dl"])
        ctx.device.process_downlink.return_value = MagicMock(  # type: ignore[attr-defined]
            accepted=True, fcnt_32=3, reject_reason=None
        )
        evidence = self._evidence(ctx, tx_offset=20.0)  # far outside any RX window
        total, attributable, unattributable = UplinkForgeryAttack()._drain_and_attribute(
            ctx,
            evidence,  # type: ignore[arg-type]
        )
        self.assertEqual((total, attributable, unattributable), (1, 0, 1))

    def test_rejected_downlink_is_unattributable(self) -> None:
        ctx = self._ctx_with_downlinks([b"\x60dl"])
        ctx.device.process_downlink.return_value = MagicMock(  # type: ignore[attr-defined]
            accepted=False, fcnt_32=-1, reject_reason="invalid_mic"
        )
        evidence = self._evidence(ctx, tx_offset=1.0)
        total, attributable, unattributable = UplinkForgeryAttack()._drain_and_attribute(
            ctx,
            evidence,  # type: ignore[arg-type]
        )
        self.assertEqual((total, attributable, unattributable), (1, 0, 1))

    def test_control_probe_ok_when_validated_response(self) -> None:
        ctx = self._ctx_with_downlinks([b"\x60dl"])
        ctx.device.process_downlink.return_value = MagicMock(  # type: ignore[attr-defined]
            accepted=True, fcnt_32=4, reject_reason=None
        )
        ok = UplinkForgeryAttack()._control_probe(ctx, _cfg())  # type: ignore[arg-type]
        self.assertTrue(ok)

    def test_control_probe_fails_when_no_response(self) -> None:
        ctx = self._ctx_with_downlinks([])
        ok = UplinkForgeryAttack()._control_probe(ctx, _cfg())  # type: ignore[arg-type]
        self.assertFalse(ok)


# ── 7. Regression — existing attacks still work ───────────────────────────────


class TestRegressionJoinReplay(unittest.TestCase):
    def test_join_devnonce_registered(self) -> None:
        from lora_attack_toolkit.attacks.bootstrap import register_builtin_attacks

        register_builtin_attacks()
        spec = AttackRegistry.get_spec("join_devnonce")
        self.assertEqual(spec.name, "join_devnonce")

    def test_join_devnonce_in_cli(self) -> None:
        self.assertIn("join_devnonce", AttackRegistry.list_attacks())


class TestRegressionUplinkReplay(unittest.TestCase):
    def test_uplink_replay_registered(self) -> None:
        from lora_attack_toolkit.attacks.bootstrap import register_builtin_attacks

        register_builtin_attacks()
        spec = AttackRegistry.get_spec("uplink_replay")
        self.assertEqual(spec.name, "uplink_replay")

    def test_uplink_replay_in_cli(self) -> None:
        self.assertIn("uplink_replay", AttackRegistry.list_attacks())

    def test_replay_channel_selection_uses_device_layer(self) -> None:
        """_select_radio_for_uplink in replay.py must call device.select_uplink_radio."""
        from lora_attack_toolkit.attacks.builtin.replay import _select_radio_for_uplink

        device = MagicMock()
        radio = _radio()
        device.select_uplink_radio.return_value = radio

        ctx = MagicMock()
        ctx.device = device
        ctx.radio = radio

        result = _select_radio_for_uplink(ctx, 7)
        device.select_uplink_radio.assert_called_once_with(7, radio)
        self.assertIs(result, radio)


class TestForgeryCancellation(unittest.TestCase):
    """Cancellation must stop transmissions and return CANCELLED."""

    def test_cancel_before_join_returns_cancelled(self) -> None:
        # Pre-set cancel: the run must return CANCELLED before the OTAA join is
        # even attempted and without transmitting any frame.
        cfg = _cfg(perform_join=True, baseline_uplink_count=2)
        ctx = _make_ctx(cfg)
        ctx.cancel_event.set()

        with patch(
            "lora_attack_toolkit.attacks.builtin.uplink_forgery.perform_otaa_join"
        ) as join_mock:
            result = UplinkForgeryAttack().run(ctx)

        self.assertEqual(result.execution_status, ExecutionStatus.CANCELLED)
        self.assertTrue(result.interrupted)
        join_mock.assert_not_called()
        ctx.gateway.forward_uplink.assert_not_called()

    def test_cancel_during_baseline_stops_forge(self) -> None:
        # Cancel after the first baseline uplink: the baseline loop stops and the
        # forged frame is never transmitted.
        cfg = _cfg(perform_join=False, baseline_uplink_count=5)
        ctx = _make_ctx(cfg)

        forwarded: list[bytes] = []

        def _forward(frame, radio):
            forwarded.append(frame)
            ctx.cancel_event.set()

        ctx.gateway.forward_uplink.side_effect = _forward

        result = UplinkForgeryAttack().run(ctx)

        self.assertEqual(result.execution_status, ExecutionStatus.CANCELLED)
        # Only the first baseline uplink was sent; no further baseline or forged frame.
        self.assertEqual(len(forwarded), 1)


if __name__ == "__main__":
    unittest.main()
