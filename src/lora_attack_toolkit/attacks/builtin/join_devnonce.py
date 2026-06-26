"""Unified DevNonce validation attack."""

from __future__ import annotations

import random
import struct
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from lora_attack_toolkit.attacks.base import BaseAttack
from lora_attack_toolkit.attacks.result import (
    AttackResult,
    Confidence,
    ExecutionStatus,
    SecurityVerdict,
)
from lora_attack_toolkit.lorawan.frames import build_join_request

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.context import AttackContext
    from lora_attack_toolkit.config import AttackTiming, JoinDevNonceConfigV1
    from lora_attack_toolkit.lorawan.time_utils import SimClock


@dataclass(frozen=True)
class JoinStepResult:
    """Result of a single join attempt."""

    dev_nonce: bytes
    join_accepted: bool
    timestamp: float


#: Canonical ``final_check`` name for the LoRaWAN 1.0.4 monotonic-DevNonce
#: behaviour test. ``lower_than_last`` is retained as a historical alias.
MONOTONIC_DEVNONCE_CHECK = "lorawan_1_0_4_monotonic_devnonce"
_MONOTONIC_DEVNONCE_ALIASES = frozenset({"lower_than_last", MONOTONIC_DEVNONCE_CHECK})


def _is_monotonic_devnonce_check(final_check: str) -> bool:
    """True for the LoRaWAN 1.0.4 monotonic-DevNonce behaviour test (+alias)."""
    return final_check in _MONOTONIC_DEVNONCE_ALIASES


@dataclass
class DevNonceResultCache:
    """Bounded cache of successful DevNonce values."""

    max_size: int
    first_accepted_devnonce: bytes | None = None
    last_accepted_devnonce: bytes | None = None
    accepted_count: int = 0
    attempt_count: int = 0
    recent_accepted_devnonces: deque[bytes] = field(init=False)
    all_accepted_devnonces: set[bytes] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.recent_accepted_devnonces = deque(maxlen=max(1, self.max_size))

    def store(self, result: JoinStepResult) -> None:
        """Record a join attempt; only accepted joins update the DevNonce data."""
        self.attempt_count += 1
        if not result.join_accepted:
            return

        if self.first_accepted_devnonce is None:
            self.first_accepted_devnonce = result.dev_nonce

        self.last_accepted_devnonce = result.dev_nonce
        self.accepted_count += 1
        self.recent_accepted_devnonces.append(result.dev_nonce)
        self.all_accepted_devnonces.add(result.dev_nonce)


class JoinDevNonceAttack(BaseAttack):
    """Unified Join attack focused on DevNonce validation."""

    name = "join_devnonce"

    def run(self, ctx: "AttackContext") -> AttackResult:
        ctx.logger.info("Starting %s attack", self.name)

        config: JoinDevNonceConfigV1 = ctx.config
        timing = self._resolve_timing(config)
        self._validate_config(config, timing)

        try:
            ctx.gateway.start()
            generation_cache = DevNonceResultCache(config.result_cache_size)
            resolved_start = self._execute_generation_phase(ctx, config, timing, generation_cache)

            if ctx.cancel_event.is_set():
                metrics = self._build_metrics(
                    config=config,
                    timing=timing,
                    generation_cache=generation_cache,
                    final_devnonce=None,
                    final_result=None,
                    generation_complete=False,
                    generation_partial=generation_cache.accepted_count > 0,
                    final_check_executed=False,
                    resolved_devnonce_start=resolved_start,
                )
                ctx.capture.metadata["devnonce_validation"] = metrics
                metrics["capture_stats"] = ctx.capture.get_stats()
                return AttackResult(
                    attack_name=self.name,
                    attack_type=self.name,
                    execution_status=ExecutionStatus.CANCELLED,
                    security_verdict=SecurityVerdict.INCONCLUSIVE,
                    confidence=Confidence.LOW,
                    interrupted=True,
                    message="Attack interrupted by user",
                    metrics=metrics,
                    captured_packets=len(ctx.capture.uplinks) + len(ctx.capture.downlinks),
                )

            generation_complete = generation_cache.accepted_count >= config.valid_join_count
            generation_partial = 0 < generation_cache.accepted_count < config.valid_join_count

            can_check, reason = self._can_execute_final_check(config, generation_cache)

            if not can_check:
                metrics = self._build_metrics(
                    config=config,
                    timing=timing,
                    generation_cache=generation_cache,
                    final_devnonce=None,
                    final_result=None,
                    generation_complete=generation_complete,
                    generation_partial=generation_partial,
                    final_check_executed=False,
                    resolved_devnonce_start=resolved_start,
                )
                ctx.capture.metadata["devnonce_validation"] = metrics
                ctx.logger.debug(
                    "Received uplinks: %s. Received downlinks: %s",
                    ctx.capture.uplinks,
                    ctx.capture.downlinks,
                )
                metrics["capture_stats"] = ctx.capture.get_stats()
                return AttackResult(
                    attack_name=self.name,
                    attack_type=self.name,
                    execution_status=ExecutionStatus.COMPLETED,
                    security_verdict=SecurityVerdict.INCONCLUSIVE,
                    confidence=Confidence.LOW,
                    message=f"Final DevNonce check was not executed: {reason}",
                    metrics=metrics,
                    captured_packets=len(ctx.capture.uplinks) + len(ctx.capture.downlinks),
                )

            final_devnonce, selection_meta = self._select_final_devnonce(config, generation_cache)

            # Apply inter-message pacing before the final check JoinRequest.
            inter_delay = ctx.timeout
            if inter_delay > 0 and not ctx.cancel_event.is_set():
                ctx.logger.debug(
                    "Inter-message delay: %.1fs before final DevNonce check", inter_delay
                )
                self._sleep_until(ctx.clock, ctx.clock.monotonic() + inter_delay, ctx.cancel_event)

            final_result = self._execute_join_step(
                ctx=ctx,
                config=config,
                timing=timing,
                dev_nonce=final_devnonce,
                attempt_index=config.valid_join_count + 1,
                phase="final",
            )

            if ctx.cancel_event.is_set():
                metrics = self._build_metrics(
                    config=config,
                    timing=timing,
                    generation_cache=generation_cache,
                    final_devnonce=final_devnonce,
                    final_result=None,
                    generation_complete=generation_complete,
                    generation_partial=generation_partial,
                    final_check_executed=False,
                    resolved_devnonce_start=resolved_start,
                    selection_meta=selection_meta,
                )
                ctx.capture.metadata["devnonce_validation"] = metrics
                metrics["capture_stats"] = ctx.capture.get_stats()
                return AttackResult(
                    attack_name=self.name,
                    attack_type=self.name,
                    execution_status=ExecutionStatus.CANCELLED,
                    security_verdict=SecurityVerdict.INCONCLUSIVE,
                    confidence=Confidence.LOW,
                    interrupted=True,
                    message="Attack interrupted by user",
                    metrics=metrics,
                    captured_packets=len(ctx.capture.uplinks) + len(ctx.capture.downlinks),
                )

            # Control probe: when the tested (replayed/invalid) DevNonce was
            # rejected, a "no JoinAccept" result is only meaningful if the path
            # and target are actually up. Send a known-valid JoinRequest with a
            # guaranteed-fresh DevNonce as a control; its outcome gates the
            # negative verdict so we never assert SECURE against a dead target.
            #
            # For monotonic (1.0.4) mode the control DevNonce must be strictly
            # greater than last_accepted so a compliant server accepts it.
            control_executed = False
            control_devnonce: bytes | None = None
            control_accepted: bool | None = None
            control_impossible_reason: str = ""
            if not final_result.join_accepted and not ctx.cancel_event.is_set():
                control_devnonce, control_impossible_reason = self._select_control_devnonce(
                    generation_cache,
                    final_devnonce,
                    final_check=config.final_check,
                )
                if control_devnonce is not None:
                    control_executed = True
                    inter_delay = ctx.timeout
                    if inter_delay > 0:
                        self._sleep_until(
                            ctx.clock, ctx.clock.monotonic() + inter_delay, ctx.cancel_event
                        )
                    control_result = self._execute_join_step(
                        ctx=ctx,
                        config=config,
                        timing=timing,
                        dev_nonce=control_devnonce,
                        attempt_index=config.valid_join_count + 2,
                        phase="control",
                    )
                    control_accepted = control_result.join_accepted

            metrics = self._build_metrics(
                config=config,
                timing=timing,
                generation_cache=generation_cache,
                final_devnonce=final_devnonce,
                final_result=final_result,
                generation_complete=generation_complete,
                generation_partial=generation_partial,
                final_check_executed=True,
                resolved_devnonce_start=resolved_start,
                selection_meta=selection_meta,
            )
            metrics["control_probe_executed"] = control_executed
            if control_impossible_reason:
                metrics["control_probe_impossible_reason"] = control_impossible_reason
            if control_executed and control_devnonce is not None:
                metrics["control_probe_devnonce"] = control_devnonce.hex()
                metrics["control_probe_accepted"] = control_accepted
            ctx.capture.metadata["devnonce_validation"] = metrics

            # If the control probe was impossible in monotonic mode, we cannot
            # distinguish "rejected because monotonic" from "unreachable" for the
            # non-final-accepted branch — report INCONCLUSIVE with an explicit reason.
            if not final_result.join_accepted and control_impossible_reason:
                reason_msg = control_impossible_reason
                inc_metrics = metrics.copy()
                inc_metrics["behavior_under_test"] = MONOTONIC_DEVNONCE_CHECK
                inc_metrics["rationale"] = reason_msg
                ctx.capture.metadata["devnonce_validation"] = inc_metrics
                inc_metrics["capture_stats"] = ctx.capture.get_stats()
                return AttackResult(
                    attack_name=self.name,
                    attack_type=self.name,
                    execution_status=ExecutionStatus.COMPLETED,
                    security_verdict=SecurityVerdict.INCONCLUSIVE,
                    confidence=Confidence.LOW,
                    message=reason_msg,
                    metrics=inc_metrics,
                    captured_packets=len(ctx.capture.uplinks) + len(ctx.capture.downlinks),
                )

            prefix = (
                "Final DevNonce check executed after partial generation phase; "
                if generation_partial
                else ""
            )
            devnonce_int = int.from_bytes(final_devnonce, "little")

            monotonic_mode = _is_monotonic_devnonce_check(config.final_check)
            if monotonic_mode:
                metrics["behavior_under_test"] = MONOTONIC_DEVNONCE_CHECK
                sv, protected, conf, message, behavior_supported = self._monotonic_devnonce_verdict(
                    config=config,
                    prefix=prefix,
                    devnonce_int=devnonce_int,
                    final_accepted=final_result.join_accepted,
                    control_accepted=control_accepted,
                )
                metrics["behavior_supported"] = behavior_supported
            elif final_result.join_accepted:
                # Verdict gating (replay modes):
                #   accepted              → VULNERABLE (NS accepted the replayed DevNonce)
                #   rejected + control ok → SECURE     (rejection is meaningful, path up)
                #   rejected + control bad→ INCONCLUSIVE (target may be unreachable)
                sv = SecurityVerdict.VULNERABLE
                protected = False
                conf = Confidence.HIGH
                message = (
                    f"{prefix}Network Server accepted the final JoinRequest "
                    f"with DevNonce {devnonce_int}"
                )
            elif control_accepted:
                sv = SecurityVerdict.SECURE
                protected = True
                conf = Confidence.HIGH
                message = (
                    f"{prefix}Network Server rejected the final JoinRequest with DevNonce "
                    f"{devnonce_int}; control join (fresh DevNonce) was accepted, so the "
                    f"rejection is meaningful"
                )
            else:
                sv = SecurityVerdict.INCONCLUSIVE
                protected = None
                conf = Confidence.LOW
                message = (
                    f"{prefix}Network Server did not answer the final JoinRequest with DevNonce "
                    f"{devnonce_int}; the control join (fresh DevNonce) was also unanswered, so "
                    f"the target may be unreachable — result is inconclusive"
                )

            metrics["capture_stats"] = ctx.capture.get_stats()
            return AttackResult(
                attack_name=self.name,
                attack_type=self.name,
                execution_status=ExecutionStatus.COMPLETED,
                security_verdict=sv,
                confidence=conf,
                target_protected=protected,
                message=message,
                metrics=metrics,
                captured_packets=len(ctx.capture.uplinks) + len(ctx.capture.downlinks),
            )
        except Exception as exc:  # noqa: BLE001
            # Top-level attack boundary: any unexpected failure becomes a
            # structured execution error (not a security verdict) so the runner
            # never crashes. Logged at error with full traceback.
            ctx.logger.exception("Attack failed: %s", exc)
            return AttackResult.failed(
                attack_name=self.name,
                attack_type=self.name,
                error=str(exc),
                metrics={},
            )
        finally:
            ctx.gateway.stop()

    def _validate_config(self, config: "JoinDevNonceConfigV1", timing: "AttackTiming") -> None:
        if config.valid_join_count < 1:
            raise ValueError("valid_join_count must be >= 1")
        if config.valid_devnonce_step < 1:
            raise ValueError("valid_devnonce_step must be >= 1")
        if config.result_cache_size < 1:
            raise ValueError("result_cache_size must be >= 1")
        # join_accept_timeout_sec must cover at least the full RX2 window.
        min_timeout = timing.rx2_delay_sec + timing.rx2_window_sec
        if timing.join_accept_timeout_sec < min_timeout:
            raise ValueError(
                f"join_accept_timeout_sec ({timing.join_accept_timeout_sec}) must be "
                f">= rx2_delay_sec + rx2_window_sec ({min_timeout})"
            )
        if config.final_check not in {
            "same_as_last",
            "lower_than_last",
            "lorawan_1_0_4_monotonic_devnonce",
            "replay_first",
            "custom",
        }:
            raise ValueError(f"Unsupported final_check: {config.final_check}")
        if config.final_check == "custom" and config.final_devnonce is None:
            raise ValueError("final_devnonce is required when final_check='custom'")

    def _monotonic_devnonce_verdict(
        self,
        *,
        config: "JoinDevNonceConfigV1",
        prefix: str,
        devnonce_int: int,
        final_accepted: bool,
        control_accepted: bool | None,
    ) -> tuple["SecurityVerdict", bool | None, "Confidence", str, bool | None]:
        """Interpret the LoRaWAN 1.0.4 monotonic-DevNonce behaviour test.

        This mode is a capability/behaviour probe, not a universal 1.0.3
        vulnerability test. It detects whether the Network Server implements the
        monotonic-DevNonce rule introduced in LoRaWAN 1.0.4 (also used in 1.1).

        Returns ``(verdict, target_protected, confidence, message, behavior_supported)``.

        * lower DevNonce rejected + fresh higher (control) accepted →
          ``behavior_supported=True`` → SECURE (NS enforces monotonic DevNonce).
        * lower DevNonce accepted → ``behavior_supported=False``:
            * target explicitly evaluated as 1.0.4-compatible → VULNERABLE
              (non-compliant with the monotonic-DevNonce requirement);
            * otherwise (unknown / 1.0.3 profile) → INCONCLUSIVE, reported as a
              capability result only — never an automatic vulnerability.
        * no answer to both tested and control joins → INCONCLUSIVE.
        """
        if final_accepted:
            behavior_supported = False
            if config.target_lorawan_1_0_4:
                return (
                    SecurityVerdict.VULNERABLE,
                    False,
                    Confidence.HIGH,
                    (
                        f"{prefix}Network Server accepted a lower DevNonce {devnonce_int}; the "
                        f"target is evaluated as LoRaWAN 1.0.4-compatible, so this violates the "
                        f"monotonic-DevNonce requirement"
                    ),
                    behavior_supported,
                )
            return (
                SecurityVerdict.INCONCLUSIVE,
                None,
                Confidence.MEDIUM,
                (
                    f"{prefix}Network Server accepted a lower DevNonce {devnonce_int}; the "
                    f"LoRaWAN 1.0.4 monotonic-DevNonce behaviour is NOT implemented. Under an "
                    f"unknown / LoRaWAN 1.0.3 profile this is a capability result, not a "
                    f"vulnerability (set device.lorawan_version=1.0.4 or 1.1 to evaluate compliance)"
                ),
                behavior_supported,
            )

        if control_accepted:
            return (
                SecurityVerdict.SECURE,
                True,
                Confidence.HIGH,
                (
                    f"{prefix}Network Server rejected the lower DevNonce {devnonce_int} and "
                    f"accepted a fresh higher control DevNonce; the LoRaWAN 1.0.4 "
                    f"monotonic-DevNonce behaviour IS implemented"
                ),
                True,
            )

        return (
            SecurityVerdict.INCONCLUSIVE,
            None,
            Confidence.LOW,
            (
                f"{prefix}Network Server did not answer the lower DevNonce {devnonce_int} nor the "
                f"fresh higher control join; the target may be unreachable — monotonic-DevNonce "
                f"behaviour could not be determined"
            ),
            None,
        )

    def _can_execute_final_check(
        self, config: "JoinDevNonceConfigV1", cache: DevNonceResultCache
    ) -> tuple[bool, str]:
        """Return (can_execute, reason_if_not) for the configured final check."""
        if config.final_check == "custom":
            return True, ""

        if config.final_check in ("same_as_last", "replay_first"):
            if cache.first_accepted_devnonce is None:
                return False, "no accepted baseline DevNonce was available"
            return True, ""

        if _is_monotonic_devnonce_check(config.final_check):
            if cache.last_accepted_devnonce is None:
                return False, "no accepted baseline DevNonce was available"
            if int.from_bytes(cache.last_accepted_devnonce, "little") == 0:
                return False, "last accepted DevNonce is 0; cannot compute a lower value"
            return True, ""

        return False, f"unsupported final_check: {config.final_check}"

    def _resolve_timing(self, config: "JoinDevNonceConfigV1") -> "AttackTiming":
        from lora_attack_toolkit.config import AttackTiming

        if config.timing is not None:
            return config.timing
        return AttackTiming()

    def _execute_generation_phase(
        self,
        ctx: "AttackContext",
        config: "JoinDevNonceConfigV1",
        timing: "AttackTiming",
        cache: DevNonceResultCache,
    ) -> int:
        ctx.logger.info("=== Generation Phase ===")

        resolved_start = self._resolve_devnonce_start(config)
        ctx.logger.info("Resolved DevNonce start: %d", resolved_start)

        for index in range(config.valid_join_count):
            if ctx.cancel_event.is_set():
                ctx.logger.info("Attack cancelled during generation phase.")
                break
            dev_nonce = self._generate_devnonce(config, index, resolved_start)
            result = self._execute_join_step(
                ctx=ctx,
                config=config,
                timing=timing,
                dev_nonce=dev_nonce,
                attempt_index=index + 1,
                phase="generation",
            )
            cache.store(result)

            # Apply inter-message pacing (scenario.timeout_sec) between requests,
            # but skip the sleep after the last message in the generation phase.
            if index < config.valid_join_count - 1 and not ctx.cancel_event.is_set():
                inter_delay = ctx.timeout
                if inter_delay > 0:
                    ctx.logger.debug(
                        "Inter-message delay: %.1fs before JoinRequest #%d",
                        inter_delay,
                        index + 2,
                    )
                    self._sleep_until(
                        ctx.clock, ctx.clock.monotonic() + inter_delay, ctx.cancel_event
                    )

        ctx.logger.info(
            "Accepted joins: %d/%d",
            cache.accepted_count,
            cache.attempt_count,
        )
        return resolved_start

    def _execute_join_step(
        self,
        ctx: "AttackContext",
        config: "JoinDevNonceConfigV1",
        timing: "AttackTiming",
        dev_nonce: bytes,
        attempt_index: int,
        phase: str,
    ) -> JoinStepResult:
        timestamp = ctx.clock.unix_time()
        # Set runtime DevNonce so process_downlink(..., expect_join=True) can derive session keys
        ctx.device.runtime.dev_nonce = dev_nonce

        # Resolve per-attempt radio: use channel plan when available
        radio = self._select_join_radio(ctx, attempt_index)

        join_request = build_join_request(
            join_eui=ctx.device._join_eui,
            dev_eui=ctx.device._dev_eui,
            dev_nonce=dev_nonce,
            app_key=ctx.device._app_key,
        )

        ctx.logger.debug(
            "JoinRequest #%d frequency=%d (region: %s)",
            attempt_index,
            radio.frequency,
            getattr(ctx.device.runtime.radio, "region_name", "none"),
        )

        ctx.gateway.forward_uplink(join_request, radio)
        ctx.device.record_uplink_airtime(radio, len(join_request), ctx.clock.monotonic())
        ctx.capture.capture_uplink(
            phy_payload=join_request,
            packet_type="join_request",
            metadata={
                "phase": phase,
                "attempt": attempt_index,
                "dev_nonce": dev_nonce.hex(),
                "final_check": config.final_check,
                "frequency_hz": radio.frequency,
            },
        )

        accepted = self._wait_for_join_accept(
            ctx=ctx,
            timing=timing,
            attempt_index=attempt_index,
            phase=phase,
            dev_nonce=dev_nonce,
        )

        ctx.logger.debug(
            "Generation attempt %d accepted=%s",
            attempt_index,
            accepted,
        )

        return JoinStepResult(
            dev_nonce=dev_nonce,
            join_accepted=accepted,
            timestamp=timestamp,
        )

    def _select_join_radio(self, ctx: "AttackContext", attempt_index: int) -> Any:
        """Return RadioMetadata for this JoinRequest, using Radio when available."""
        from lora_attack_toolkit.config import RadioMetadata
        from lora_attack_toolkit.lorawan.radio import Radio

        radio = ctx.device.runtime.radio
        if isinstance(radio, Radio):
            tx = radio.select_join_channel(attempt_index - 1, now=ctx.clock.unix_time())
            return RadioMetadata(
                frequency=tx.frequency_hz,
                data_rate=tx.data_rate,
                rssi=ctx.radio.rssi,
                snr=ctx.radio.snr,
            )
        return ctx.radio

    def _wait_for_join_accept(
        self,
        ctx: "AttackContext",
        timing: "AttackTiming",
        attempt_index: int,
        phase: str,
        dev_nonce: bytes,
    ) -> bool:
        start = ctx.clock.monotonic()
        windows = (
            ("RX1", timing.rx1_delay_sec, timing.rx1_window_sec),
            ("RX2", timing.rx2_delay_sec, timing.rx2_window_sec),
        )

        for window_name, window_start_offset, window_size in windows:
            if ctx.cancel_event.is_set():
                return False
            if not self._sleep_until(ctx.clock, start + window_start_offset, ctx.cancel_event):
                return False
            window_deadline = start + window_start_offset + window_size

            ctx.logger.debug("Opening window %s", window_name)

            while ctx.clock.monotonic() < window_deadline:
                if ctx.cancel_event.is_set():
                    return False
                remaining = window_deadline - ctx.clock.monotonic()
                if remaining <= 0:
                    break

                downlink = ctx.gateway.await_downlink(timeout_sec=min(remaining, 0.1))
                if downlink is None:
                    # Advance the clock so the window eventually closes (instant
                    # under FakeClock, real under WallClock).
                    ctx.clock.sleep(min(remaining, 0.1), ctx.cancel_event)
                    continue
                try:
                    ctx.logger.debug(
                        "Received JoinAccept downlink in %s: %s", window_name, downlink
                    )
                    result = ctx.device.process_downlink(downlink, expect_join=True)
                    if not result.accepted:
                        ctx.logger.warning(
                            "JoinAccept received but process_downlink rejected it: %s",
                            result.reject_reason,
                        )
                        continue
                except (ValueError, KeyError, struct.error) as exc:
                    ctx.logger.warning(
                        "JoinAccept received but process_downlink failed: %s",
                        exc,
                    )
                    continue

                ctx.capture.capture_downlink(
                    phy_payload=downlink,
                    packet_type="join_accept",
                    metadata={
                        "phase": phase,
                        "attempt": attempt_index,
                        "window": window_name,
                        "dev_nonce": dev_nonce.hex(),
                    },
                )
                return True

        return False

    def _select_control_devnonce(
        self,
        cache: DevNonceResultCache,
        final_devnonce: bytes,
        *,
        final_check: str = "",
    ) -> tuple[bytes | None, str]:
        """Pick a guaranteed-fresh DevNonce for the control probe.

        For non-monotonic modes returns the lowest 16-bit DevNonce that was
        neither accepted during the generation phase nor used as the tested
        final DevNonce.

        For the LoRaWAN 1.0.4 monotonic-DevNonce modes the control DevNonce
        must additionally be **strictly greater than last_accepted** so that a
        compliant 1.0.4 server accepts it (and thus proves the path is up).
        If no such DevNonce exists (e.g. last_accepted == 0xFFFF), returns
        ``(None, reason)`` and the caller must report INCONCLUSIVE.

        Returns:
            ``(devnonce, "")`` on success, or ``(None, reason)`` when no valid
            control DevNonce can be found.
        """
        used = set(cache.all_accepted_devnonces)
        used.add(final_devnonce)

        if _is_monotonic_devnonce_check(final_check):
            last = cache.last_accepted_devnonce
            if last is None:
                return None, "monotonic control probe impossible: no last accepted DevNonce"
            last_value = int.from_bytes(last, "little")
            if last_value >= 0xFFFF:
                return (
                    None,
                    "monotonic control probe impossible: no DevNonce above last accepted "
                    f"(last_accepted=0x{last_value:04X})",
                )
            for value in range(last_value + 1, 0x10000):
                candidate = value.to_bytes(2, "little")
                if candidate not in used:
                    return candidate, ""
            return (
                None,
                "monotonic control probe impossible: all DevNonces above last accepted are used",
            )

        for value in range(0x10000):
            candidate = value.to_bytes(2, "little")
            if candidate not in used:
                return candidate, ""
        return None, "no unused DevNonce available for the control probe"

    def _select_final_devnonce(
        self, config: "JoinDevNonceConfigV1", cache: DevNonceResultCache
    ) -> tuple[bytes, dict[str, Any]]:
        """Select the final DevNonce and return (devnonce, extra_metrics)."""
        if config.final_check == "same_as_last":
            if cache.last_accepted_devnonce is None:
                raise ValueError("No accepted DevNonce available for final_check='same_as_last'")
            return cache.last_accepted_devnonce, {}

        if _is_monotonic_devnonce_check(config.final_check):
            if cache.last_accepted_devnonce is None:
                raise ValueError(
                    f"No accepted DevNonce available for final_check={config.final_check!r}"
                )
            last_value = int.from_bytes(cache.last_accepted_devnonce, "little")
            if last_value == 0:
                raise ValueError("Cannot generate a lower DevNonce than 0")

            candidate = last_value - 1
            attempts = 0
            while candidate >= 0:
                candidate_bytes = candidate.to_bytes(2, "little")
                attempts += 1
                if candidate_bytes not in cache.all_accepted_devnonces:
                    return candidate_bytes, {
                        "lower_than_last_candidate_search_attempts": attempts,
                    }
                candidate -= 1

            raise ValueError(
                "Cannot select unused lower-than-last DevNonce. "
                "Increase valid_devnonce_step or valid_devnonce_start."
            )

        if config.final_check == "replay_first":
            if cache.first_accepted_devnonce is None:
                raise ValueError("No accepted DevNonce available for final_check='replay_first'")
            return cache.first_accepted_devnonce, {}

        if config.final_check == "custom":
            if config.final_devnonce is None:
                raise ValueError("final_devnonce is required when final_check='custom'")
            return self._devnonce_to_bytes(int(config.final_devnonce)), {}

        raise ValueError(f"Unsupported final_check: {config.final_check}")

    def _resolve_devnonce_start(self, config: "JoinDevNonceConfigV1") -> int:
        """Resolve valid_devnonce_start to a concrete integer."""
        if config.valid_devnonce_start == "random":
            rng = random.Random(config.devnonce_seed)
            return rng.randint(0, 0xFFFF)
        return int(config.valid_devnonce_start)

    def _generate_devnonce(
        self, config: "JoinDevNonceConfigV1", index: int, resolved_start: int
    ) -> bytes:
        value = resolved_start + (index * config.valid_devnonce_step)
        if config.valid_devnonce_wrap:
            value = value & 0xFFFF
        return self._devnonce_to_bytes(value)

    @staticmethod
    def _devnonce_to_bytes(value: int) -> bytes:
        if value < 0 or value > 0xFFFF:
            raise ValueError(f"DevNonce must fit in 16 bits: {value}")
        return value.to_bytes(2, "little")

    def _sleep_until(self, clock: "SimClock", deadline: float, cancel_event=None) -> bool:
        """Sleep in short increments until deadline. Returns False if cancelled.

        Uses the injected clock so unit tests with a :class:`FakeClock` advance
        instantly and deterministically instead of blocking on real time.
        """
        while clock.monotonic() < deadline:
            if cancel_event is not None and cancel_event.is_set():
                return False
            remaining = deadline - clock.monotonic()
            if remaining <= 0:
                break
            if not clock.sleep(min(0.05, remaining), cancel_event):
                return False
        return True

    def _build_metrics(
        self,
        config: "JoinDevNonceConfigV1",
        timing: "AttackTiming",
        generation_cache: DevNonceResultCache,
        final_devnonce: bytes | None,
        final_result: JoinStepResult | None,
        generation_complete: bool,
        generation_partial: bool,
        final_check_executed: bool,
        resolved_devnonce_start: int | None = None,
        selection_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        metrics: dict[str, Any] = {
            "attack_type": self.name,
            "final_check": config.final_check,
            "valid_join_count": config.valid_join_count,
            "generation_attempt_count": generation_cache.attempt_count,
            "accepted_generation_count": generation_cache.accepted_count,
            "failed_generation_count": generation_cache.attempt_count
            - generation_cache.accepted_count,
            "generation_complete": generation_complete,
            "generation_partial": generation_partial,
            "final_check_executed": final_check_executed,
            "result_cache_size": config.result_cache_size,
            "valid_devnonce_wrap": config.valid_devnonce_wrap,
            "first_accepted_devnonce": (
                generation_cache.first_accepted_devnonce.hex()
                if generation_cache.first_accepted_devnonce is not None
                else None
            ),
            "last_accepted_devnonce": (
                generation_cache.last_accepted_devnonce.hex()
                if generation_cache.last_accepted_devnonce is not None
                else None
            ),
            "recent_accepted_devnonces": [
                value.hex() for value in generation_cache.recent_accepted_devnonces
            ],
            "timing": {
                "join_accept_timeout_sec": timing.join_accept_timeout_sec,
            },
        }

        if resolved_devnonce_start is not None:
            metrics["resolved_devnonce_start"] = resolved_devnonce_start
        if config.devnonce_seed is not None:
            metrics["devnonce_seed"] = config.devnonce_seed

        if final_devnonce is not None:
            metrics["final_devnonce"] = final_devnonce.hex()
            metrics["final_devnonce_int"] = int.from_bytes(final_devnonce, "little")
            metrics["final_devnonce_was_previously_used"] = (
                final_devnonce in generation_cache.all_accepted_devnonces
            )
            metrics["final_devnonce_relation"] = config.final_check

        if final_result is not None:
            metrics["final_result_known"] = True
            metrics["final_join_accepted"] = final_result.join_accepted
            metrics["final_join_timestamp"] = final_result.timestamp
        else:
            metrics["final_result_known"] = False

        if selection_meta:
            metrics.update(selection_meta)

        return metrics
