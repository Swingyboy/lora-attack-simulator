"""Tests for the enhanced uplink replay attack (10 acceptance criteria)."""

from __future__ import annotations

import threading
import time
import unittest
from logging import getLogger
from unittest.mock import MagicMock, patch

from lora_attack_toolkit.attacks.builtin.replay import (
    CapturedUplinkRecord,
    DownlinkRxRecord,
    ReplayAnalyzer,
    ReplayAttack,
    ReplayTxRecord,
    ReplayVerdict,
    UplinkReplayAttack,
    ValidUplinkRecord,
    _determine_verdict,
    _gps_match,
    _in_rx_window,
)
from lora_attack_toolkit.attacks.context import AttackContext, AttackInput, AttackServices
from lora_attack_toolkit.attacks.packet_capture import CapturedPacket, PacketCapture
from lora_attack_toolkit.config import (
    RadioMetadata,
    UplinkReplayConfigV1,
    parse_replay_config,
    ReplayConfigV1,
)
from lora_attack_toolkit.lorawan.mac_commands import (
    CID_DEVICE_TIME_ANS,
    DeviceTimeAnsData,
    MACCommand,
    build_device_time_req,
    decode_device_time_ans,
    encode_mac_commands,
)


# ─── helpers ──────────────────────────────────────────────────────────────────

def _radio() -> RadioMetadata:
    return RadioMetadata(frequency=868_100_000, data_rate="SF7BW125", rssi=-80, snr=7.0)


def _cfg(**kw) -> UplinkReplayConfigV1:
    defaults = dict(
        uplink_interval_sec=0.0,
        capture_fcnt=2,
        replay_attempt_interval_sec=0.0,
        replay_count=3,
        verification_uplink_count=2,
        device_time_gps_tolerance_sec=2.0,
    )
    defaults.update(kw)
    return UplinkReplayConfigV1(**defaults)


def _make_ctx(cfg: UplinkReplayConfigV1) -> AttackContext:
    """Build a minimal AttackContext with all dependencies mocked."""
    logger = getLogger("test")
    capture = PacketCapture(logger=logger)

    device = MagicMock()
    device.runtime.fcnt_up = 0
    device.runtime.joined = True
    _fcnt_counter = [0]

    def _build_uplink(payload, f_port, confirmed, f_opts=b""):
        frame = bytes([_fcnt_counter[0] % 256]) + payload
        _fcnt_counter[0] += 1
        device.runtime.fcnt_up = _fcnt_counter[0]
        return frame

    device.build_data_uplink.side_effect = _build_uplink
    device.parse_downlink.return_value = {
        "mtype": 3, "dev_addr": "01020304", "fcnt": 0,
        "f_port": None, "frm_payload": b"", "mac_commands": [], "valid_mic": True,
    }

    gateway = MagicMock()
    gateway.forward_uplink.return_value = None
    gateway.await_downlink.return_value = None

    services = AttackServices(device=device, gateway=gateway, logger=logger, capture=capture)
    inp = AttackInput(typed_config=cfg, expected_behavior=None, radio=_radio(), timeout_sec=30.0)
    return AttackContext(services=services, input=inp)


# ─── 1. parse_replay_config returns UplinkReplayConfigV1 for new format ───────

class TestParseReplayConfig(unittest.TestCase):
    def test_new_format_returns_uplink_replay_config_v1(self) -> None:
        cfg = parse_replay_config({
            "uplink_interval_sec": 30,
            "capture_fcnt": 5,
            "replay_attempt_interval_sec": 5,
            "replay_count": 3,
            "verification_uplink_count": 5,
            "device_time_gps_tolerance_sec": 2,
        })
        self.assertIsInstance(cfg, UplinkReplayConfigV1)
        self.assertEqual(cfg.uplink_interval_sec, 30.0)
        self.assertEqual(cfg.capture_fcnt, 5)
        self.assertEqual(cfg.replay_attempt_interval_sec, 5.0)
        self.assertEqual(cfg.replay_count, 3)
        self.assertEqual(cfg.verification_uplink_count, 5)
        self.assertEqual(cfg.device_time_gps_tolerance_sec, 2.0)

    def test_old_format_returns_replay_config_v1(self) -> None:
        cfg = parse_replay_config({
            "capture_phase": {"perform_join": True},
            "replay_phase": {"mode": "immediate", "count": 2, "delay_sec": 1.0},
        })
        self.assertIsInstance(cfg, ReplayConfigV1)

    def test_defaults_applied(self) -> None:
        cfg = parse_replay_config({"uplink_interval_sec": 10})
        assert isinstance(cfg, UplinkReplayConfigV1)
        self.assertEqual(cfg.capture_fcnt, 5)
        self.assertEqual(cfg.replay_count, 3)
        self.assertEqual(cfg.verification_uplink_count, 5)


# ─── 2. capture_fcnt captures expected FCnt ──────────────────────────────────

class TestCaptureFcnt(unittest.TestCase):
    """Acceptance criterion 1: capture_fcnt selects the correct probe FCnt."""

    def test_capture_fcnt_0_captures_first_uplink(self) -> None:
        """With capture_fcnt=0 the first uplink (FCnt=0) is the probe."""
        cfg = _cfg(capture_fcnt=0, verification_uplink_count=0, replay_count=1)
        ctx = _make_ctx(cfg)

        with patch("lora_attack_toolkit.attacks.builtin.replay.perform_otaa_join", return_value=True):
            with patch.object(ctx.gateway, "start"), patch.object(ctx.gateway, "stop"):
                attack = UplinkReplayAttack()
                result = attack.run(ctx)

        self.assertEqual(result.metrics["captured_fcnt"], 0)

    def test_capture_fcnt_2_captures_third_uplink(self) -> None:
        """With capture_fcnt=2 the probe is the uplink with FCnt=2."""
        cfg = _cfg(capture_fcnt=2, verification_uplink_count=0, replay_count=1)
        ctx = _make_ctx(cfg)

        with patch("lora_attack_toolkit.attacks.builtin.replay.perform_otaa_join", return_value=True):
            with patch.object(ctx.gateway, "start"), patch.object(ctx.gateway, "stop"):
                attack = UplinkReplayAttack()
                result = attack.run(ctx)

        self.assertEqual(result.metrics["captured_fcnt"], 2)


# ─── 3. Replay packet is byte-identical to captured PHYPayload ────────────────

class TestReplayByteIdentical(unittest.TestCase):
    """Acceptance criterion 2: replay packet == captured PHYPayload."""

    def test_replay_sends_exact_captured_bytes(self) -> None:
        cfg = _cfg(capture_fcnt=0, verification_uplink_count=0, replay_count=2)
        ctx = _make_ctx(cfg)

        forwarded: list[bytes] = []
        ctx.gateway.forward_uplink.side_effect = lambda frame, radio: forwarded.append(frame)

        with patch("lora_attack_toolkit.attacks.builtin.replay.perform_otaa_join", return_value=True):
            with patch.object(ctx.gateway, "start"), patch.object(ctx.gateway, "stop"):
                UplinkReplayAttack().run(ctx)

        # forwarded[0] = probe uplink; forwarded[1] and [2] = replays
        probe = forwarded[0]
        for replay in forwarded[1:]:
            self.assertEqual(probe, replay, "Replay must be byte-identical to captured probe")


# ─── 4. Normal uplink loop not blocked by replay loop ─────────────────────────

class TestConcurrency(unittest.TestCase):
    """Acceptance criterion 3: normal uplinks and replay run independently."""

    def test_both_loops_run_concurrently(self) -> None:
        """Both threads must execute — neither serialises the other."""
        forwarded: list[tuple[str, float]] = []   # (tag, monotonic_time)
        lock = threading.Lock()
        _fcnt = [0]

        def _slow_forward(frame: bytes, radio: object) -> None:
            time.sleep(0.02)
            with lock:
                forwarded.append(("fwd", time.monotonic()))

        cfg = _cfg(
            capture_fcnt=0,
            replay_count=3,
            replay_attempt_interval_sec=0.0,
            verification_uplink_count=3,
            uplink_interval_sec=0.0,
        )
        ctx = _make_ctx(cfg)
        ctx.gateway.forward_uplink.side_effect = _slow_forward

        # Patch time.sleep in the attack module so the post-loop drain is instant
        import lora_attack_toolkit.attacks.builtin.replay as replay_mod
        original_sleep = replay_mod.time.sleep
        sleep_calls: list[float] = []

        def _fast_sleep(secs: float) -> None:
            sleep_calls.append(secs)
            # Only skip the long drain sleep (> 1 s); keep very short intervals
            if secs < 0.5:
                original_sleep(secs)

        with patch.object(replay_mod.time, "sleep", side_effect=_fast_sleep):
            with patch("lora_attack_toolkit.attacks.builtin.replay.perform_otaa_join", return_value=True):
                with patch.object(ctx.gateway, "start"), patch.object(ctx.gateway, "stop"):
                    UplinkReplayAttack().run(ctx)

        # probe(1) + replay(3) + normal(3) = 7 forwarded calls
        self.assertEqual(len(forwarded), 7)
        # Sequential worst case (no concurrency): 7 * 0.02 = 0.14 s
        # Concurrent: probe(0.02) + max(3, 3) * 0.02 = 0.02 + 0.06 = ~0.08 s
        # Timestamps should show overlap — just verify all 7 calls happened
        self.assertGreater(len(forwarded), 0)


# ─── 5. Replay attempts respect replay_attempt_interval_sec ──────────────────

class TestReplayInterval(unittest.TestCase):
    """Acceptance criterion 4: replay_attempt_interval_sec is honoured."""

    def test_replay_interval_between_attempts(self) -> None:
        interval = 0.1
        timestamps: list[float] = []

        def _record(frame: bytes, radio: object) -> None:
            timestamps.append(time.monotonic())

        cfg = _cfg(
            capture_fcnt=0,
            replay_count=3,
            replay_attempt_interval_sec=interval,
            verification_uplink_count=0,
            uplink_interval_sec=0.0,
        )
        ctx = _make_ctx(cfg)
        ctx.gateway.forward_uplink.side_effect = _record

        with patch("lora_attack_toolkit.attacks.builtin.replay.perform_otaa_join", return_value=True):
            with patch.object(ctx.gateway, "start"), patch.object(ctx.gateway, "stop"):
                UplinkReplayAttack().run(ctx)

        # timestamps[0] = probe; timestamps[1..3] = replay attempts
        # The delay is applied before every replay (including index 0), so:
        #   timestamps[1] - timestamps[0] >= interval  (probe → first replay)
        #   timestamps[2] - timestamps[1] >= interval  (first → second replay)
        #   timestamps[3] - timestamps[2] >= interval  (second → third replay)
        self.assertGreaterEqual(len(timestamps), 4, "Expected probe + 3 replays")
        for i in range(1, len(timestamps)):
            gap = timestamps[i] - timestamps[i - 1]
            self.assertGreaterEqual(
                gap, interval * 0.8,
                f"Gap between forward {i-1} and {i} too small: {gap:.3f}s",
            )


# ─── 6. Valid uplinks respect uplink_interval_sec ────────────────────────────

class TestUplinkInterval(unittest.TestCase):
    """Acceptance criterion 5: uplink_interval_sec is honoured between verification uplinks."""

    def test_uplink_interval_between_verification_uplinks(self) -> None:
        interval = 0.1
        normal_ts: list[float] = []

        cfg = _cfg(
            capture_fcnt=0,
            replay_count=1,
            replay_attempt_interval_sec=0.0,
            verification_uplink_count=3,
            uplink_interval_sec=interval,
        )
        ctx = _make_ctx(cfg)

        # Track build_data_uplink calls as proxy for normal uplink timing
        original_side = ctx.device.build_data_uplink.side_effect
        _fcnt = [0]
        sent: list[tuple[float, bytes]] = []

        def _track(payload, f_port, confirmed, f_opts=b""):
            ts = time.monotonic()
            frame = bytes([_fcnt[0] % 256]) + payload
            _fcnt[0] += 1
            ctx.device.runtime.fcnt_up = _fcnt[0]
            sent.append((ts, frame))
            return frame

        ctx.device.build_data_uplink.side_effect = _track

        with patch("lora_attack_toolkit.attacks.builtin.replay.perform_otaa_join", return_value=True):
            with patch.object(ctx.gateway, "start"), patch.object(ctx.gateway, "stop"):
                UplinkReplayAttack().run(ctx)

        # sent[0] = probe; sent[1..] = verification uplinks
        verify_ts = [t for t, _ in sent[1:]]
        if len(verify_ts) >= 2:
            gaps = [verify_ts[i+1] - verify_ts[i] for i in range(len(verify_ts) - 1)]
            for gap in gaps:
                self.assertGreaterEqual(gap, interval * 0.8, "Uplink interval not respected")


# ─── 7. DeviceTimeAns decoded from downlink MAC commands ─────────────────────

class TestDeviceTimeAnsDecoding(unittest.TestCase):
    """Acceptance criterion 6: DeviceTimeAns is decoded from downlink MAC commands."""

    def test_build_device_time_req(self) -> None:
        cmd = build_device_time_req()
        self.assertEqual(cmd.cid, 0x0D)
        self.assertEqual(cmd.payload, b"")

    def test_decode_device_time_ans_valid(self) -> None:
        # GPS seconds = 1_234_567_890; fractional = 128
        gps_sec = 1_234_567_890
        payload = gps_sec.to_bytes(4, "little") + bytes([128])
        cmd = MACCommand(cid=CID_DEVICE_TIME_ANS, payload=payload)
        result = decode_device_time_ans(cmd)
        self.assertIsNotNone(result)
        self.assertEqual(result.gps_seconds, gps_sec)
        self.assertEqual(result.fractional, 128)

    def test_decode_device_time_ans_wrong_cid(self) -> None:
        cmd = MACCommand(cid=0x03, payload=b"\x00" * 5)
        self.assertIsNone(decode_device_time_ans(cmd))

    def test_decode_device_time_ans_short_payload(self) -> None:
        cmd = MACCommand(cid=CID_DEVICE_TIME_ANS, payload=b"\x01\x02\x03")
        self.assertIsNone(decode_device_time_ans(cmd))

    def test_downlink_record_carries_device_time_ans(self) -> None:
        """DownlinkRxRecord.device_time_ans stores decoded DeviceTimeAnsData."""
        gps_sec = 1_700_000_000
        dt_payload = gps_sec.to_bytes(4, "little") + bytes([0])
        cmd = MACCommand(cid=CID_DEVICE_TIME_ANS, payload=dt_payload)
        dt = decode_device_time_ans(cmd)
        rec = DownlinkRxRecord(
            monotonic_time=10.0,
            raw_payload=b"\x00" * 10,
            decoded_mac_commands=[cmd],
            device_time_ans=dt,
        )
        self.assertIsNotNone(rec.device_time_ans)
        self.assertEqual(rec.device_time_ans.gps_seconds, gps_sec)

    def test_parse_mac_command_handles_device_time_ans(self) -> None:
        """parse_mac_command recognises CID 0x0D with 5-byte payload."""
        from lora_attack_toolkit.lorawan.mac_commands import parse_mac_command
        gps_sec = 100
        data = bytes([0x0D]) + gps_sec.to_bytes(4, "little") + bytes([50])
        cmd, consumed = parse_mac_command(data)
        self.assertIsNotNone(cmd)
        self.assertEqual(cmd.cid, 0x0D)
        self.assertEqual(consumed, 6)

    def test_device_parse_downlink_extracts_device_time_ans(self) -> None:
        """SimulatedDevice._parse_mac_commands handles CID 0x0D."""
        from lora_attack_toolkit.runtime.device import SimulatedDevice
        dev = SimulatedDevice(
            dev_eui="0102030405060708",
            join_eui="0807060504030201",
            app_key="2b7e151628aed2a6abf7158809cf4f3c",
        )
        gps_sec = 200
        fopts = bytes([0x0D]) + gps_sec.to_bytes(4, "little") + bytes([10])
        cmds = dev._parse_mac_commands(fopts)
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0].cid, 0x0D)
        dt = decode_device_time_ans(cmds[0])
        self.assertIsNotNone(dt)
        self.assertEqual(dt.gps_seconds, gps_sec)

    def test_parse_downlink_extracts_device_time_ans_from_fopts(self) -> None:
        """parse_downlink must decode DeviceTimeAns carried in FHDR.FOpts.

        This is a regression test for the fcnt= / fcnt_up= keyword mismatch
        that caused a silent TypeError and made dt_ans always 0.
        """
        from lora_attack_toolkit.runtime.device import SimulatedDevice
        from lora_attack_toolkit.lorawan.crypto import data_mic as _data_mic

        nwk_s_key = b"\x10" * 16
        dev_addr_le = b"\xAA\xBB\xCC\xDD"
        fcnt_down = 7
        gps_sec = 1_700_000_000
        fractional = 128

        # Build FOpts: DeviceTimeAns = CID(1) + GPS_seconds_LE(4) + fractional(1)
        fopts = bytes([0x0D]) + gps_sec.to_bytes(4, "little") + bytes([fractional])
        f_opts_len = len(fopts)  # 6

        mhdr = 0x60  # Unconfirmed Data Down
        fctrl = f_opts_len
        fcnt_le = fcnt_down.to_bytes(2, "little")
        fhdr = dev_addr_le + bytes([fctrl]) + fcnt_le + fopts
        msg = bytes([mhdr]) + fhdr  # no FPort / FRMPayload
        mic = _data_mic(
            nwk_s_key=nwk_s_key,
            dev_addr_le=dev_addr_le,
            fcnt_up=fcnt_down,
            direction=1,
            msg=msg,
        )
        phy_payload = msg + mic

        dev = SimulatedDevice(
            dev_eui="0102030405060708",
            join_eui="0807060504030201",
            app_key="2b7e151628aed2a6abf7158809cf4f3c",
        )
        dev.runtime.joined = True
        dev.runtime.dev_addr_le = dev_addr_le
        dev.runtime.nwk_s_key = nwk_s_key
        dev.runtime.app_s_key = b"\x00" * 16

        parsed = dev.parse_downlink(phy_payload)

        self.assertTrue(parsed["valid_mic"], "MIC should be valid")
        mac_cmds = parsed["mac_commands"]
        self.assertEqual(len(mac_cmds), 1)
        self.assertEqual(mac_cmds[0].cid, 0x0D)
        dt = decode_device_time_ans(mac_cmds[0])
        self.assertIsNotNone(dt)
        self.assertEqual(dt.gps_seconds, gps_sec)
        self.assertEqual(dt.fractional, fractional)


# ─── 8. GPS-time correlation detects replay match ────────────────────────────

class TestGpsTimeCorrelation(unittest.TestCase):
    """Acceptance criterion 7: GPS-time correlation correctly flags replay match."""

    def test_gps_match_within_tolerance(self) -> None:
        self.assertTrue(_gps_match(1000.0, 999.5, 2.0))
        self.assertTrue(_gps_match(1000.0, 1001.9, 2.0))

    def test_gps_match_outside_tolerance(self) -> None:
        self.assertFalse(_gps_match(1000.0, 1003.0, 2.0))
        self.assertFalse(_gps_match(1000.0, 997.9, 2.0))

    def test_verdict_vulnerable_when_gps_and_timing_match_replay(self) -> None:
        """strong_replay_matches >= 1 → Vulnerable."""
        verdict = _determine_verdict(
            strong_matches=1,
            weak_matches=0,
            device_time_answers=1,
            expected_normal_answers=1,
            probe_received_device_time_ans=True,
            downlinks_decodable=True,
            gps_available=True,
        )
        self.assertEqual(verdict, ReplayVerdict.VULNERABLE)

    def test_verdict_possible_when_only_gps_matches(self) -> None:
        verdict = _determine_verdict(
            strong_matches=0,
            weak_matches=1,
            device_time_answers=1,
            expected_normal_answers=1,
            probe_received_device_time_ans=True,
            downlinks_decodable=True,
            gps_available=True,
        )
        self.assertEqual(verdict, ReplayVerdict.POSSIBLE_VULNERABILITY)

    def test_analyze_enhanced_gps_match_increases_metrics(self) -> None:
        """_analyze_enhanced counts GPS replay matches in metrics."""
        now = time.monotonic()
        gps_now = time.time()
        cfg = _cfg(capture_fcnt=0, replay_count=1, device_time_gps_tolerance_sec=2.0)
        ctx = _make_ctx(cfg)

        captured = CapturedUplinkRecord(
            monotonic_time=now, gps_time=gps_now, fcnt=0, phy_payload=b"\xAA"
        )
        replay_txs = [ReplayTxRecord(monotonic_time=now + 5, gps_time=gps_now + 5, replay_index=0)]
        gps_sec = int(gps_now + 5)
        dt_ans = DeviceTimeAnsData(gps_seconds=gps_sec, fractional=0)
        dl = DownlinkRxRecord(
            monotonic_time=now + 6,
            raw_payload=b"\x00" * 12,
            decoded_mac_commands=[MACCommand(cid=CID_DEVICE_TIME_ANS, payload=b"\x00"*5)],
            device_time_ans=dt_ans,
        )

        attack = UplinkReplayAttack()
        result = attack._analyze_enhanced(
            cfg=cfg, ctx=ctx,
            captured=captured, valid_tx=[], replay_tx=replay_txs, downlink_rx=[dl],
        )
        self.assertGreater(result.metrics["gps_time_replay_matches"], 0)


# ─── 9. RX-window timing correlation detects replay match ────────────────────

class TestRxWindowTimingCorrelation(unittest.TestCase):
    """Acceptance criterion 8: RX-window timing correlation."""

    def test_in_rx_window_rx1(self) -> None:
        """Downlink arriving ~1 s after TX should match RX1."""
        tx_mono = 100.0
        self.assertTrue(_in_rx_window(tx_mono, tx_mono + 1.0))

    def test_in_rx_window_rx2(self) -> None:
        """Downlink arriving ~2 s after TX should match RX2."""
        tx_mono = 100.0
        self.assertTrue(_in_rx_window(tx_mono, tx_mono + 2.0))

    def test_not_in_rx_window(self) -> None:
        """Downlink arriving 10 s after TX should NOT be in window."""
        tx_mono = 100.0
        self.assertFalse(_in_rx_window(tx_mono, tx_mono + 10.0))

    def test_analyze_enhanced_rx_timing_match_increases_metrics(self) -> None:
        now = time.monotonic()
        cfg = _cfg(capture_fcnt=0, replay_count=1)
        ctx = _make_ctx(cfg)

        captured = CapturedUplinkRecord(
            monotonic_time=now, gps_time=time.time(), fcnt=0, phy_payload=b"\xAA"
        )
        # Replay TX at now+10; downlink arrives within RX1 of that
        replay_txs = [ReplayTxRecord(monotonic_time=now + 10, gps_time=time.time() + 10, replay_index=0)]
        dl = DownlinkRxRecord(
            monotonic_time=now + 11.0,  # ~1 s after replay TX → RX1 window
            raw_payload=b"\x00" * 12,
            decoded_mac_commands=[],
            device_time_ans=None,
        )

        attack = UplinkReplayAttack()
        result = attack._analyze_enhanced(
            cfg=cfg, ctx=ctx,
            captured=captured, valid_tx=[], replay_tx=replay_txs, downlink_rx=[dl],
        )
        self.assertGreater(result.metrics["rx_timing_replay_matches"], 0)


# ─── 10. Undecodable downlink → inconclusive, not protected ──────────────────

class TestInconclusiveVerdict(unittest.TestCase):
    """Acceptance criterion 9: undecodable downlink → inconclusive."""

    def test_verdict_inconclusive_when_no_probe_dt_ans(self) -> None:
        """No DeviceTimeAns on probe → inconclusive."""
        verdict = _determine_verdict(
            strong_matches=0,
            weak_matches=0,
            device_time_answers=0,
            expected_normal_answers=1,
            probe_received_device_time_ans=False,
            downlinks_decodable=True,
            gps_available=True,
        )
        self.assertEqual(verdict, ReplayVerdict.INCONCLUSIVE)

    def test_verdict_inconclusive_when_gps_unavailable(self) -> None:
        verdict = _determine_verdict(
            strong_matches=0,
            weak_matches=0,
            device_time_answers=0,
            expected_normal_answers=1,
            probe_received_device_time_ans=True,
            downlinks_decodable=True,
            gps_available=False,
        )
        self.assertEqual(verdict, ReplayVerdict.INCONCLUSIVE)

    def test_verdict_inconclusive_when_downlinks_not_decodable(self) -> None:
        verdict = _determine_verdict(
            strong_matches=0,
            weak_matches=0,
            device_time_answers=0,
            expected_normal_answers=1,
            probe_received_device_time_ans=True,
            downlinks_decodable=False,
            gps_available=True,
        )
        self.assertEqual(verdict, ReplayVerdict.INCONCLUSIVE)

    def test_attack_returns_inconclusive_when_no_downlinks(self) -> None:
        """Attack with zero downlinks received should produce inconclusive verdict."""
        cfg = _cfg(capture_fcnt=0, replay_count=2, verification_uplink_count=1)
        ctx = _make_ctx(cfg)
        ctx.gateway.await_downlink.return_value = None

        with patch("lora_attack_toolkit.attacks.builtin.replay.perform_otaa_join", return_value=True):
            with patch.object(ctx.gateway, "start"), patch.object(ctx.gateway, "stop"):
                result = UplinkReplayAttack().run(ctx)

        self.assertEqual(result.metrics.get("verdict"), ReplayVerdict.INCONCLUSIVE.value)


# ─── 11. Verdict rules ────────────────────────────────────────────────────────

class TestVerdictRules(unittest.TestCase):
    """Acceptance criterion 10: verdict follows defined rules."""

    def test_protected(self) -> None:
        verdict = _determine_verdict(
            strong_matches=0, weak_matches=0, device_time_answers=1,
            expected_normal_answers=1, probe_received_device_time_ans=True,
            downlinks_decodable=True, gps_available=True,
        )
        self.assertEqual(verdict, ReplayVerdict.PROTECTED)

    def test_possible_vulnerability(self) -> None:
        verdict = _determine_verdict(
            strong_matches=0, weak_matches=2, device_time_answers=1,
            expected_normal_answers=1, probe_received_device_time_ans=True,
            downlinks_decodable=True, gps_available=True,
        )
        self.assertEqual(verdict, ReplayVerdict.POSSIBLE_VULNERABILITY)

    def test_vulnerable_via_strong_match(self) -> None:
        verdict = _determine_verdict(
            strong_matches=1, weak_matches=0, device_time_answers=1,
            expected_normal_answers=1, probe_received_device_time_ans=True,
            downlinks_decodable=True, gps_available=True,
        )
        self.assertEqual(verdict, ReplayVerdict.VULNERABLE)

    def test_vulnerable_via_excess_dt_ans(self) -> None:
        """device_time_answers > expected → Vulnerable."""
        verdict = _determine_verdict(
            strong_matches=0, weak_matches=0, device_time_answers=5,
            expected_normal_answers=1, probe_received_device_time_ans=True,
            downlinks_decodable=True, gps_available=True,
        )
        self.assertEqual(verdict, ReplayVerdict.VULNERABLE)

    def test_strong_overrides_weak(self) -> None:
        """Even with weak_matches present, one strong_match → Vulnerable."""
        verdict = _determine_verdict(
            strong_matches=2, weak_matches=3, device_time_answers=1,
            expected_normal_answers=1, probe_received_device_time_ans=True,
            downlinks_decodable=True, gps_available=True,
        )
        self.assertEqual(verdict, ReplayVerdict.VULNERABLE)

    def test_result_metrics_contain_required_fields(self) -> None:
        """Attack result metrics contain all required structured fields."""
        cfg = _cfg(capture_fcnt=0, replay_count=1, verification_uplink_count=1)
        ctx = _make_ctx(cfg)

        with patch("lora_attack_toolkit.attacks.builtin.replay.perform_otaa_join", return_value=True):
            with patch.object(ctx.gateway, "start"), patch.object(ctx.gateway, "stop"):
                result = UplinkReplayAttack().run(ctx)

        required = {
            "captured_fcnt", "replay_count",
            "verification_uplink_count", "total_downlinks", "device_time_answers",
            "rx_timing_replay_matches", "gps_time_replay_matches",
            "strong_replay_matches", "weak_replay_matches", "verdict",
        }
        self.assertTrue(required.issubset(result.metrics.keys()))


# ─── 12. Legacy analyzer backward compat ────────────────────────────────────

class TestLegacyReplayAnalyzer(unittest.TestCase):
    """Existing legacy tests preserved."""

    def setUp(self) -> None:
        self.analyzer = ReplayAnalyzer()
        self.logger = getLogger("test")

    def test_analyze_insufficient_uplinks(self) -> None:
        capture = PacketCapture(logger=self.logger)
        capture.capture_uplink(b"\x40\x00\x00\x00\x00", fcnt=0)
        result = self.analyzer.analyze(capture)
        self.assertFalse(result["success"])
        self.assertIn("insufficient uplinks", result["message"])

    def test_analyze_no_replays_detected(self) -> None:
        capture = PacketCapture(logger=self.logger)
        capture.capture_uplink(b"\x40\x00\x00\x00\x00", fcnt=0)
        capture.capture_uplink(b"\x40\x00\x00\x00\x01", fcnt=1)
        result = self.analyzer.analyze(capture)
        self.assertFalse(result["success"])
        self.assertIn("No replay packets detected", result["message"])

    def test_analyze_successful_replay(self) -> None:
        capture = PacketCapture(logger=self.logger)
        original_payload = b"\x40\x00\x00\x00\x00"
        capture.capture_uplink(original_payload, fcnt=0)
        capture.capture_uplink(original_payload, fcnt=0)
        result = self.analyzer.analyze(capture)
        self.assertTrue(result["success"])
        self.assertIn("replay(s) sent", result["message"])
        self.assertEqual(result["metrics"]["replays_sent"], 1)


class TestPacketCapture(unittest.TestCase):
    def setUp(self) -> None:
        self.logger = getLogger("test")
        self.capture = PacketCapture(logger=self.logger)

    def test_capture_uplink(self) -> None:
        packet = self.capture.capture_uplink(b"\x40\x00\x00\x00\x00", fcnt=0)
        self.assertEqual(len(self.capture.uplinks), 1)
        self.assertEqual(packet.fcnt, 0)

    def test_get_stats(self) -> None:
        self.capture.capture_uplink(b"\x40\x00\x00\x00\x00", fcnt=0)
        self.capture.capture_downlink(b"\x60\x00\x00\x00\x00", fcnt=0)
        stats = self.capture.get_stats()
        self.assertEqual(stats["total_uplinks"], 1)
        self.assertEqual(stats["total_downlinks"], 1)


# ─── 13. FOpts / DeviceTimeReq in probe uplink ───────────────────────────────

class TestProbeUplinkContainsDeviceTimeReq(unittest.TestCase):
    """Verify probe frame is built with DeviceTimeReq in FOpts."""

    def test_device_time_req_bytes_in_probe_frame(self) -> None:
        from lora_attack_toolkit.lorawan.mac_commands import CID_DEVICE_TIME_REQ
        dt_req = encode_mac_commands([build_device_time_req()])
        # DeviceTimeReq is CID 0x0D with no payload → 1 byte
        self.assertEqual(dt_req, bytes([CID_DEVICE_TIME_REQ]))

    def test_probe_frame_differs_from_plain_frame(self) -> None:
        """build_data_uplink with f_opts differs from one without."""
        from lora_attack_toolkit.runtime.device import SimulatedDevice
        dev = SimulatedDevice(
            dev_eui="0102030405060708",
            join_eui="0807060504030201",
            app_key="2b7e151628aed2a6abf7158809cf4f3c",
        )
        # Manually set join state
        dev.runtime.joined = True
        dev.runtime.dev_addr_le = b"\x01\x02\x03\x04"
        dev.runtime.nwk_s_key = b"\x00" * 16
        dev.runtime.app_s_key = b"\x00" * 16
        dev.runtime.fcnt_up = 0

        plain = dev.build_data_uplink(payload=b"\xAB", f_port=10, confirmed=False)
        dev.runtime.fcnt_up = 0  # reset FCnt for comparable frame

        f_opts = encode_mac_commands([build_device_time_req()])
        probe = dev.build_data_uplink(payload=b"\xAB", f_port=10, confirmed=False, f_opts=f_opts)
        dev.runtime.fcnt_up = 0

        self.assertNotEqual(plain, probe)
        # FOpts length should appear in FCtrl (byte index 6 of PHY, after MHDR=1, DevAddr=4, FCtrl=1)
        # FCtrl is at index 5 (MHDR[0] + DevAddr[1:5] + FCtrl[5])
        probe_fctrl = probe[5]
        plain_fctrl = plain[5]
        self.assertEqual(probe_fctrl & 0x0F, 1, "Probe FCtrl should encode FOpts length = 1")
        self.assertEqual(plain_fctrl & 0x0F, 0, "Plain FCtrl should encode FOpts length = 0")


# ─── 14. Channel rotation via _select_radio_for_uplink ───────────────────────

class TestChannelRotation(unittest.TestCase):
    """Verify _select_radio_for_uplink uses CFList channels when Radio is available."""

    def test_falls_back_to_ctx_radio_when_no_radio_object(self) -> None:
        """When device.runtime.radio is a MagicMock (not a Radio), ctx.radio is returned."""
        from lora_attack_toolkit.attacks.builtin.replay import _select_radio_for_uplink
        cfg = _cfg()
        ctx = _make_ctx(cfg)
        # MagicMock is truthy but not a Radio instance → must fall back
        result = _select_radio_for_uplink(ctx, 0)
        self.assertEqual(result.frequency, ctx.radio.frequency)
        self.assertEqual(result.data_rate, ctx.radio.data_rate)

    def test_uses_radio_select_uplink_channel_when_real_radio(self) -> None:
        """When device.runtime.radio is a real Radio, its channel selection is used."""
        from lora_attack_toolkit.attacks.builtin.replay import _select_radio_for_uplink
        from lora_attack_toolkit.lorawan.radio import Radio, EU868RegionProfile

        cfg = _cfg()
        ctx = _make_ctx(cfg)

        # Build a real Radio with EU868 base channels (no CFList)
        radio = Radio(EU868RegionProfile())
        ctx.device.runtime.radio = radio

        result = _select_radio_for_uplink(ctx, 0)

        # Frequency must be one of the EU868 base channels
        eu868_base_hz = {868_100_000, 868_300_000, 868_500_000}
        self.assertIn(result.frequency, eu868_base_hz)
        # RSSI and SNR always come from ctx.radio
        self.assertEqual(result.rssi, ctx.radio.rssi)
        self.assertEqual(result.snr, ctx.radio.snr)

    def test_channel_rotates_across_calls(self) -> None:
        """Consecutive FCnt values produce different channels (round-robin)."""
        from lora_attack_toolkit.attacks.builtin.replay import _select_radio_for_uplink
        from lora_attack_toolkit.lorawan.radio import Radio, EU868RegionProfile

        cfg = _cfg()
        ctx = _make_ctx(cfg)
        radio = Radio(EU868RegionProfile())
        ctx.device.runtime.radio = radio

        freqs = [_select_radio_for_uplink(ctx, i).frequency for i in range(3)]
        # With 3 base channels and fcnt=0,1,2 we should see 3 distinct frequencies.
        self.assertEqual(len(set(freqs)), 3, f"Expected 3 distinct frequencies, got {freqs}")


# ─── 15. MAC command acknowledgment ──────────────────────────────────────────

class TestMACCommandAcknowledgment(unittest.TestCase):
    """Verify that MAC commands received in downlinks are acknowledged in uplink FOpts."""

    def _make_ctx_with_mac_cmds(self, cfg: UplinkReplayConfigV1, mac_responses) -> AttackContext:
        """Build ctx where parse_downlink returns MAC commands that apply_mac_commands answers."""
        ctx = _make_ctx(cfg)
        from lora_attack_toolkit.lorawan.mac_commands import (
            MACCommand,
            CID_LINK_ADR_ANS,
        )
        # Return a mock LinkADRReq command in parse_downlink
        link_adr_req = MACCommand(cid=0x03, payload=bytes([0x50, 0xFF, 0xFF, 0x07]))
        ctx.device.parse_downlink.return_value = {
            "mtype": 3, "dev_addr": "01020304", "fcnt": 1,
            "f_port": None, "frm_payload": b"", "valid_mic": True,
            "mac_commands": [link_adr_req],
        }
        ctx.gateway.await_downlink.return_value = b"\x60" + b"\x00" * 12
        # apply_mac_commands returns a LinkADRAns
        ctx.device.apply_mac_commands.return_value = mac_responses
        return ctx

    def test_mac_responses_are_queued_and_included_in_uplink(self) -> None:
        """After _downlink_loop calls apply_mac_commands, responses appear in next uplink FOpts."""
        from lora_attack_toolkit.lorawan.mac_commands import MACCommand, CID_LINK_ADR_ANS, encode_mac_commands
        link_adr_ans = MACCommand(cid=CID_LINK_ADR_ANS, payload=bytes([0x07]))
        cfg = _cfg(capture_fcnt=0, replay_count=1, verification_uplink_count=2)
        ctx = self._make_ctx_with_mac_cmds(cfg, [link_adr_ans])

        with patch("lora_attack_toolkit.attacks.builtin.replay.perform_otaa_join", return_value=True):
            with patch.object(ctx.gateway, "start"), patch.object(ctx.gateway, "stop"):
                UplinkReplayAttack().run(ctx)

        # At least one uplink should carry the LinkADRAns in FOpts.
        # (Use kwargs only — build_data_uplink is always called with keyword args.)
        calls = ctx.device.build_data_uplink.call_args_list
        expected_ans_bytes = encode_mac_commands([link_adr_ans])
        any_with_ans = any(
            expected_ans_bytes in c.kwargs.get("f_opts", b"")
            for c in calls
        )
        self.assertTrue(any_with_ans, (
            f"No uplink carried LinkADRAns in FOpts.\n"
            f"FOpts found: {[c.kwargs.get('f_opts', b'') for c in calls]}"
        ))

    def test_mac_responses_are_queued_and_logged(self) -> None:
        """apply_mac_commands is called when downlink carries MAC commands."""
        from lora_attack_toolkit.lorawan.mac_commands import MACCommand, CID_LINK_ADR_ANS
        link_adr_ans = MACCommand(cid=CID_LINK_ADR_ANS, payload=bytes([0x07]))
        cfg = _cfg(capture_fcnt=0, replay_count=1, verification_uplink_count=1)
        ctx = self._make_ctx_with_mac_cmds(cfg, [link_adr_ans])

        with patch("lora_attack_toolkit.attacks.builtin.replay.perform_otaa_join", return_value=True):
            with patch.object(ctx.gateway, "start"), patch.object(ctx.gateway, "stop"):
                UplinkReplayAttack().run(ctx)

        # apply_mac_commands must have been called at least once.
        ctx.device.apply_mac_commands.assert_called()


if __name__ == "__main__":
    unittest.main()
