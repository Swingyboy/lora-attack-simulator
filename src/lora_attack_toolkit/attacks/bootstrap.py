"""Bootstrap function to register built-in attacks.

This module provides explicit registration of all built-in attack plugins.
Called during app startup to populate the attack registry.
"""

from __future__ import annotations

import logging

from lora_attack_toolkit.attacks.builtin.join_devnonce import JoinDevNonceAttack
from lora_attack_toolkit.attacks.builtin.mac_abuse import MACCommandAbuse
from lora_attack_toolkit.attacks.builtin.replay import UplinkReplayAttack
from lora_attack_toolkit.attacks.builtin.uplink_forgery import UplinkForgeryAttack
from lora_attack_toolkit.attacks.registry import AttackRegistry, AttackSpec
from lora_attack_toolkit.config import (
    parse_join_devnonce_config,
    parse_mac_command_config,
    parse_replay_config,
    parse_uplink_forgery_config,
)

logger = logging.getLogger(__name__)


def _register_builtin(spec: AttackSpec) -> None:
    """Register a builtin attack once."""
    try:
        existing = AttackRegistry.get_spec(spec.name)
    except ValueError:
        AttackRegistry.register(spec)
        return

    if (
        existing.attack_class is spec.attack_class
        and existing.config_parser is spec.config_parser
        and existing.aliases == spec.aliases
    ):
        return

    raise ValueError(f"Attack type '{spec.name}' is already registered")


def register_builtin_attacks() -> None:
    """Register all built-in attack plugins.

    This function must be called during app startup to populate
    the attack registry with built-in attack types.

    Raises:
        ValueError: If duplicate registration detected
    """
    logger.info("Registering built-in attack plugins...")

    # Uplink Replay Attack
    _register_builtin(
        AttackSpec(
            name="uplink_replay",
            attack_class=UplinkReplayAttack,
            config_parser=parse_replay_config,
            aliases=[],
            title="Uplink Replay Attack",
            category="replay",
            attack_id="uplink-replay-v1",
            description="Replay captured uplink frames to test frame counter validation",
        )
    )

    # Join Replay Attack (with multiple modes)
    _register_builtin(
        AttackSpec(
            name="join_devnonce",
            attack_class=JoinDevNonceAttack,
            config_parser=parse_join_devnonce_config,
            title="Join DevNonce Validation",
            category="join_devnonce",
            attack_id="join-devnonce-v1",
            description="Test DevNonce replay protection with unified validation modes",
        )
    )

    # MAC Command Injection/Abuse
    _register_builtin(
        AttackSpec(
            name="mac_command_injection",
            attack_class=MACCommandAbuse,
            config_parser=parse_mac_command_config,
            aliases=["mac_malformed"],
            title="MAC Command Injection",
            category="mac_abuse",
            attack_id="mac-command-injection-v1",
            description="Inject legitimate or malformed MAC commands",
        )
    )

    # Uplink Forgery Attack
    _register_builtin(
        AttackSpec(
            name="uplink_forgery",
            attack_class=UplinkForgeryAttack,
            config_parser=parse_uplink_forgery_config,
            aliases=[],
            title="Uplink Forgery Attack",
            category="forgery",
            attack_id="uplink-forgery-v1",
            description=(
                "Construct attacker-controlled uplinks to evaluate Network Server "
                "MIC validation, FCnt validation, session binding, and DevAddr validation"
            ),
        )
    )

    logger.info(
        "Registered %d attack types: %s",
        len(AttackRegistry.list_attacks()),
        ", ".join(AttackRegistry.list_attacks()),
    )
