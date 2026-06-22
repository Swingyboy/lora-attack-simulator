"""MAC command abuse and ADR manipulation attack — EXPERIMENTAL prototype.

# TODO: Implement MAC-command abuse as a complete LoRaWAN protocol flow.
# The current prototype must not be used for security verdicts or diploma
# experiments until it transmits and verifies a complete LoRaWAN frame.

This module is intentionally kept out of the registered attack set (see
``attacks/bootstrap.py``) and excluded from the supported CLI attack choices.
It is retained as future work only.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from lora_attack_toolkit.attacks.analyzer import AttackAnalyzer
from lora_attack_toolkit.attacks.base import BaseAttack
from lora_attack_toolkit.attacks.packet_capture import PacketCapture
from lora_attack_toolkit.attacks.result import (
    AttackResult,
    Confidence,
    ExecutionStatus,
    SecurityVerdict,
)
from lora_attack_toolkit.attacks.validation import validate_criteria
from lora_attack_toolkit.lorawan.join import perform_otaa_join
from lora_attack_toolkit.lorawan.mac_commands import (
    CID_DEV_STATUS_REQ,
    CID_LINK_ADR_REQ,
    CID_NEW_CHANNEL_REQ,
    CID_RX_PARAM_SETUP_REQ,
    MACCommand,
    build_dev_status_req,
    build_link_adr_req,
    build_malformed_mac_command,
    build_new_channel_req,
    build_rx_param_setup_req,
)

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.context import AttackContext
    from lora_attack_toolkit.config import ExpectedBehavior
    from lora_attack_toolkit.experimental.config import MACCommandConfigV1

from lora_attack_toolkit.experimental.config import MACCommandConfigV1

# LEGACY analysis path: MACCommandAnalyzer is the current production analyzer
# used in MACCommandInjectionAttack.run().  It infers verdict from downlink
# counts and ADR state — a heuristic approach.
# A future replacement should decode each received downlink frame and check
# MAC command payloads directly rather than counting packets.
# Do not remove until the run() path is updated to a protocol-level analyzer.


class MACCommandAnalyzer(AttackAnalyzer):
    """Analyzer for MAC command abuse attack results."""

    def analyze(
        self, capture: PacketCapture, expected: ExpectedBehavior | None = None
    ) -> dict[str, Any]:
        """Analyze MAC command abuse attack results."""
        stats = capture.get_stats()

        # Count phases
        uplinks_before = 0
        uplinks_after = 0
        mac_commands_injected = 0
        malformed_commands = 0
        adr_state_changes = 0

        for packet in capture.uplinks:
            phase = packet.metadata.get("phase", "")
            if phase == "setup":
                uplinks_before += 1
            elif phase == "execute":
                if packet.metadata.get("mac_command_type"):
                    mac_commands_injected += 1
                    if packet.metadata.get("malformed"):
                        malformed_commands += 1
                else:
                    uplinks_after += 1
                    if packet.metadata.get("adr_state"):
                        adr_state_changes += 1

        if mac_commands_injected == 0:
            return {
                "success": False,
                "message": "No MAC commands were injected",
                "metrics": {"uplinks_captured": stats["total_uplinks"], "mac_commands_injected": 0},
            }

        # Build metrics
        metrics = {
            "mac_commands_injected": mac_commands_injected,
            "uplinks_before_attack": uplinks_before,
            "uplinks_after_attack": uplinks_after,
            "total_uplinks": stats["total_uplinks"],
            "total_downlinks": stats["total_downlinks"],
            "device_responded": uplinks_after > 0,
            "malformed_commands": malformed_commands,
            "adr_state_changes": adr_state_changes,
        }

        message = f"MAC command abuse executed: {mac_commands_injected} command(s) injected"
        if malformed_commands > 0:
            message += f"; malformed command(s): {malformed_commands}"
        if uplinks_after > 0:
            message += f", device sent {uplinks_after} uplink(s) after"
        if adr_state_changes > 0:
            message += f"; ADR state change observed ({adr_state_changes})"

        # Base result
        result = {
            "success": True,
            "message": message,
            "metrics": metrics,
        }

        # Add validation if expected behavior provided
        if expected:
            validation = validate_criteria(
                attack_type="mac_command_injection",
                criteria=expected.security_criteria,
                metrics=metrics,
                capture_stats=stats,
                secure_behavior=expected.secure_behavior,
            )
            result.update(validation.to_dict())
            result["validation_summary"] = validation.get_summary()

        return result


class MACCommandAbuse(BaseAttack):
    """
    MAC command abuse attack using new simplified API.

    Tests Network Server handling of legitimate or malformed MAC commands.
    """

    name = "mac_command_injection"

    def run(self, ctx: AttackContext) -> AttackResult:
        """
        Execute MAC command abuse attack.

        Args:
            ctx: Attack context with all services and typed configuration

        Returns:
            AttackResult with execution outcome
        """
        ctx.logger.info("Starting %s attack", self.name)

        try:
            # Get typed configuration
            config: MACCommandConfigV1 = ctx.config

            # Track ADR state
            adr_state = {
                "data_rate": 0,
                "tx_power": 0,
                "nb_trans": 1,
            }

            # Start gateway
            ctx.logger.info("Starting gateway...")
            ctx.gateway.start()
            time.sleep(0.5)

            # Perform OTAA join
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
                    attack_type="mac_command_injection",
                    error="OTAA join failed",
                    message="OTAA join failed - cannot proceed",
                )

            ctx.logger.info("OTAA join successful")

            # Send baseline uplinks
            ctx.logger.info("Sending baseline uplinks...")
            for i in range(2):
                try:
                    payload = bytes.fromhex("010203")
                    uplink = ctx.device.build_data_uplink(
                        payload=payload, f_port=10, confirmed=False
                    )

                    ctx.capture.capture_uplink(
                        phy_payload=uplink,
                        fcnt=ctx.device.runtime.fcnt_up - 1,
                        packet_type="data_up",
                        metadata={
                            "phase": "setup",
                            "baseline": True,
                            "adr_state": dict(adr_state),
                        },
                    )

                    ctx.gateway.forward_uplink(uplink, ctx.radio)
                    time.sleep(0.3)
                except RuntimeError as e:
                    ctx.logger.warning("Could not build baseline uplink: %s", e)

            time.sleep(0.5)

            # Build and inject MAC command
            ctx.logger.info(
                "Injecting MAC command: type=%s, malformed=%s",
                config.command_type,
                config.malformed,
            )

            if config.malformed:
                mac_command = self._build_malformed_command(config)
            else:
                mac_command = self._build_legitimate_command(config)

            # Capture MAC command injection
            mac_command_bytes = mac_command.to_bytes()
            ctx.capture.capture_uplink(
                phy_payload=mac_command_bytes,
                packet_type="mac_command",
                metadata={
                    "phase": "execute",
                    "mac_command_type": config.command_type,
                    "cid": mac_command.cid,
                    "payload_hex": mac_command.payload.hex(),
                    "malformed": config.malformed,
                    "malformation_type": config.malformation_type if config.malformed else None,
                },
            )

            # Update ADR state if LinkADRReq
            if config.command_type == "LinkADRReq" and not config.malformed:
                self._update_adr_state(mac_command, adr_state, ctx)

            # Send follow-up uplink
            time.sleep(0.5)
            try:
                payload = bytes.fromhex("040506")
                uplink = ctx.device.build_data_uplink(payload=payload, f_port=10, confirmed=False)

                ctx.capture.capture_uplink(
                    phy_payload=uplink,
                    fcnt=ctx.device.runtime.fcnt_up - 1,
                    packet_type="data_up",
                    metadata={
                        "phase": "execute",
                        "after_mac_command": True,
                        "adr_state": dict(adr_state),
                    },
                )

                ctx.gateway.forward_uplink(uplink, ctx.radio)
            except RuntimeError as e:
                ctx.logger.warning("Could not build follow-up uplink: %s", e)

            time.sleep(1.0)

            # Stop gateway
            ctx.gateway.stop()

            # Analyze results
            ctx.logger.info("Analyzing results...")
            analyzer = MACCommandAnalyzer()
            analysis = analyzer.analyze(ctx.capture, ctx.expected)

            # Map legacy analysis success to standardized verdict
            legacy_success = analysis.get("success", True)
            sv = SecurityVerdict.SECURE if legacy_success else SecurityVerdict.INCONCLUSIVE
            return AttackResult(
                attack_name=self.name,
                attack_type="mac_command_injection",
                execution_status=ExecutionStatus.COMPLETED,
                security_verdict=sv,
                confidence=Confidence.LOW,
                message=analysis["message"],
                metrics=analysis["metrics"],
                captured_packets=len(ctx.capture.uplinks) + len(ctx.capture.downlinks),
                validation_summary=analysis.get("validation_summary"),
                criteria_met=analysis.get("criteria_met"),
            )

        except Exception as e:  # noqa: BLE001
            ctx.logger.exception("Attack failed: %s", e)
            return AttackResult.failed(
                attack_name=self.name,
                attack_type="mac_command_injection",
                error=str(e),
            )

    def _build_legitimate_command(
        self,
        config: MACCommandConfigV1,
    ) -> MACCommand:
        """Build legitimate MAC command based on command_type."""
        params = config.parameters or {}

        if config.command_type == "LinkADRReq":
            return build_link_adr_req(
                data_rate=params.get("data_rate", 5),
                tx_power=params.get("tx_power", 2),
                ch_mask=params.get("ch_mask", 0x00FF),
                redundancy=params.get("redundancy", 1),
            )
        elif config.command_type == "RXParamSetupReq":
            return build_rx_param_setup_req(
                rx1_dr_offset=params.get("rx1_dr_offset", 0),
                rx2_data_rate=params.get("rx2_data_rate", 0),
                frequency=params.get("frequency", 869525000),
            )
        elif config.command_type == "NewChannelReq":
            return build_new_channel_req(
                ch_index=params.get("ch_index", 3),
                frequency=params.get("frequency", 867100000),
                max_dr=params.get("max_dr", 5),
                min_dr=params.get("min_dr", 0),
            )
        elif config.command_type == "DevStatusReq":
            return build_dev_status_req()
        else:
            raise ValueError(f"Unsupported command type: {config.command_type}")

    def _build_malformed_command(
        self,
        config: MACCommandConfigV1,
    ) -> MACCommand:
        """Build malformed MAC command for attack."""
        cid_map = {
            "LinkADRReq": CID_LINK_ADR_REQ,
            "RXParamSetupReq": CID_RX_PARAM_SETUP_REQ,
            "NewChannelReq": CID_NEW_CHANNEL_REQ,
            "DevStatusReq": CID_DEV_STATUS_REQ,
        }

        cid = cid_map.get(config.command_type, CID_LINK_ADR_REQ)
        params = config.parameters or {}

        return build_malformed_mac_command(
            cid=cid,
            malformation_type=config.malformation_type or "truncate",
            **params,
        )

    def _update_adr_state(
        self,
        mac_command: MACCommand,
        adr_state: dict[str, Any],
        ctx: AttackContext | None = None,
    ) -> None:
        """Update ADR state based on LinkADRReq command."""
        if len(mac_command.payload) < 4:
            return

        data_rate_tx_power = mac_command.payload[0]
        data_rate = (data_rate_tx_power >> 4) & 0x0F
        tx_power = data_rate_tx_power & 0x0F
        redundancy = mac_command.payload[3]
        nb_trans = redundancy & 0x0F

        adr_state["data_rate"] = data_rate
        adr_state["tx_power"] = tx_power
        adr_state["nb_trans"] = nb_trans

        if ctx is not None:
            ctx.logger.info(
                "ADR state updated: DR=%s, TXPower=%s, NbTrans=%s",
                data_rate,
                tx_power,
                nb_trans,
                extra=adr_state,
            )
