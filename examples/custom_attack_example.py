"""Example: How to Add a Custom Attack Plugin

This file demonstrates how to extend the attack simulator with a custom attack.
The plugin system makes it easy to add new attacks without modifying framework code.

Steps:
1. Create a config dataclass (optional but recommended).
2. Create an attack class inheriting from BaseAttack and implement run(ctx).
3. Register the attack with AttackSpec.
4. Create a scenario JSON that uses your attack type.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from lora_attack_toolkit.attacks.base import BaseAttack
from lora_attack_toolkit.attacks.context import AttackContext
from lora_attack_toolkit.attacks.result import AttackResult
from lora_attack_toolkit.attacks.registry import AttackRegistry, AttackSpec


# ─── Step 1: Config dataclass ─────────────────────────────────────────────────


@dataclass
class CustomAttackConfig:
    burst_size: int = 10
    interval_sec: float = 0.5


def parse_custom_attack_config(raw: dict[str, Any]) -> CustomAttackConfig:
    """Parse the attack.config block from the scenario JSON."""
    burst_size = raw.get("burst_size", 10)
    interval_sec = raw.get("interval_sec", 0.5)
    if burst_size < 1:
        raise ValueError("burst_size must be >= 1")
    if interval_sec < 0:
        raise ValueError("interval_sec must be >= 0")
    return CustomAttackConfig(burst_size=burst_size, interval_sec=interval_sec)


# ─── Step 2: Attack class ─────────────────────────────────────────────────────


class CustomAttack(BaseAttack):
    """Example attack: sends a configurable burst of data uplinks."""

    name = "custom_uplink_burst"

    def run(self, ctx: AttackContext) -> AttackResult:
        """Execute the attack.

        ctx provides access to device, gateway, logger, radio metadata,
        timeout, and the parsed typed_config.
        """
        cfg: CustomAttackConfig = ctx.input.typed_config
        logger = ctx.logger

        logger.info("Custom attack: performing OTAA join")
        from lora_attack_toolkit.lorawan.join import perform_otaa_join

        joined = perform_otaa_join(
            device=ctx.device,
            gateway=ctx.gateway,
            radio=ctx.radio,
            timeout_sec=10.0,
            logger=logger,
        )
        if not joined:
            return AttackResult(
                attack_name=self.name,
                attack_type=self.name,
                success=False,
                message="OTAA join failed",
            )

        logger.info("OTAA join successful; sending %d uplinks", cfg.burst_size)
        for i in range(cfg.burst_size):
            payload = f"uplink-{i}".encode()
            uplink_frame = ctx.device.build_data_uplink(
                payload=payload, f_port=1, confirmed=False
            )
            ctx.gateway.forward_uplink(uplink_frame, ctx.radio)
            if i < cfg.burst_size - 1:
                time.sleep(cfg.interval_sec)

        logger.info("Burst complete: %d uplinks sent", cfg.burst_size)
        return AttackResult(
            attack_name=self.name,
            attack_type=self.name,
            success=True,
            message=f"Sent {cfg.burst_size} uplinks",
        )


# ─── Step 3: Register the attack ─────────────────────────────────────────────


AttackRegistry.register(
    AttackSpec(
        name="custom_uplink_burst",
        title="Custom Uplink Burst",
        category="custom",
        description="Send a configurable burst of uplinks to test rate limiting",
        attack_class=CustomAttack,
        config_parser=parse_custom_attack_config,
    )
)


# ─── Step 4: Example scenario JSON ───────────────────────────────────────────
#
#  Save as scenario.json and run with:
#    lorat
#    > load scenario.json
#    > run
#
#  {
#    "scenario": {
#      "timeout_sec": 30
#    },
#    "attack": {
#      "type": "custom_uplink_burst",
#      "config": {
#        "burst_size": 20,
#        "interval_sec": 0.1
#      }
#    },
#    "expected": {
#      "profile": "default"
#    }
#  }
