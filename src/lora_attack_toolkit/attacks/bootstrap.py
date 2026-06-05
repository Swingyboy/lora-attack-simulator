"""Bootstrap function to register built-in attacks.

This module provides explicit registration of all built-in attack plugins.
Called during app startup to populate the attack registry.
"""

from __future__ import annotations

import logging

from lora_attack_toolkit.attacks.builtin.join_abuse import JoinAbuseAttack
from lora_attack_toolkit.attacks.builtin.join_replay import JoinReplayAttack
from lora_attack_toolkit.attacks.builtin.mac_abuse import MACCommandAbuse
from lora_attack_toolkit.attacks.registry import AttackRegistry, AttackSpec
from lora_attack_toolkit.attacks.builtin.replay import UplinkReplayAttack
from lora_attack_toolkit.core.schema_v1 import (
    parse_join_flood_config,
    parse_join_replay_config,
    parse_mac_command_config,
    parse_replay_config,
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
            description="Replay captured uplink frames to test frame counter validation",
        )
    )
    
    # Join Replay Attack (with multiple modes)
    _register_builtin(
        AttackSpec(
            name="join_replay",
            attack_class=JoinReplayAttack,
            config_parser=parse_join_replay_config,
            aliases=["replay", "duplicate_devnonce"],
            description="Test DevNonce replay protection with various strategies",
        )
    )
    
    # Join Flood Attack
    _register_builtin(
        AttackSpec(
            name="join_flood",
            attack_class=JoinAbuseAttack,
            config_parser=parse_join_flood_config,
            aliases=[],
            description="Flood Network Server with join requests",
        )
    )
    
    # MAC Command Injection/Abuse
    _register_builtin(
        AttackSpec(
            name="mac_command_injection",
            attack_class=MACCommandAbuse,
            config_parser=parse_mac_command_config,
            aliases=["mac_malformed"],
            description="Inject legitimate or malformed MAC commands",
        )
    )
    
    logger.info(
        f"Registered {len(AttackRegistry.list_attacks())} attack types: "
        f"{', '.join(AttackRegistry.list_attacks())}"
    )
