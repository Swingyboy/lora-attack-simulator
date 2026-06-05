"""Bootstrap function to register built-in attacks.

This module provides explicit registration of all built-in attack plugins.
Called during app startup to populate the attack registry.
"""

from __future__ import annotations

import logging
from typing import Any

from lora_attack_toolkit.attacks.base import BaseAttack
from lora_attack_toolkit.attacks.config import AttackConfig
from lora_attack_toolkit.attacks.builtin.join_abuse import JoinAbuseAttack
from lora_attack_toolkit.attacks.builtin.join_replay import JoinReplayAttack
from lora_attack_toolkit.attacks.builtin.join_replay_generators import (
    DuplicateDevNonceGenerator,
    MemoryDepthDevNonceGenerator,
    RollbackDevNonceGenerator,
)
from lora_attack_toolkit.attacks.builtin.join_replay_verifiers import (
    DuplicateDevNonceVerifier,
    MemoryDepthVerifier,
    RollbackDevNonceVerifier,
)
from lora_attack_toolkit.attacks.builtin.mac_abuse import MACCommandAbuse
from lora_attack_toolkit.attacks.registry import AttackRegistry, AttackSpec
from lora_attack_toolkit.attacks.builtin.replay import UplinkReplayAttack
from lora_attack_toolkit.core.schema_v1 import (
    parse_join_flood_config,
    parse_join_replay_config,
    parse_mac_command_config,
    parse_replay_config,
)
from lora_attack_toolkit.core.schema import RadioMetadata

logger = logging.getLogger(__name__)


def _create_replay_attack(
    config: AttackConfig,
    device: Any,
    gateway: Any,
    logger: logging.Logger,
    radio: RadioMetadata,
    attack_config: dict[str, Any],
    expected: Any,
) -> ReplayAttack:
    """Factory for ReplayAttack."""
    replay_config = parse_replay_config(attack_config)
    
    return ReplayAttack(
        config=config,
        device=device,
        gateway=gateway,
        logger=logger,
        radio=radio,
        replay_mode=replay_config.replay_phase.mode,
        delay_sec=replay_config.replay_phase.delay_sec,
        burst_count=replay_config.replay_phase.count,
        burst_interval_sec=0.1,
        expected=expected,
    )


def _create_join_replay_attack(
    config: AttackConfig,
    device: Any,
    gateway: Any,
    logger: logging.Logger,
    radio: RadioMetadata,
    attack_config: dict[str, Any],
    expected: Any,
) -> BaseAttack:
    """Factory for JoinReplayAttack (or JoinAbuseAttack for legacy mode)."""
    join_config = parse_join_replay_config(attack_config)
    
    # Get attack mode (with backwards compatibility)
    mode = join_config.mode or "duplicate_devnonce"
    # Legacy: mode="replay" → "duplicate_devnonce"
    if mode == "replay":
        mode = "duplicate_devnonce"
    
    # For duplicate_devnonce, use legacy JoinAbuseAttack (has setup logic)
    if mode == "duplicate_devnonce":
        return JoinAbuseAttack(
            config=config,
            device=device,
            gateway=gateway,
            logger=logger,
            radio=radio,
            mode="replay",
            flood_count=join_config.replay_count,
            flood_interval_sec=join_config.delay_sec,
            replay_delay_sec=join_config.delay_sec,
            virtual_devices=1,
            expected=expected,
            timing=join_config.timing,
        )
    
    # For other modes, use new JoinReplayAttack
    if mode == "devnonce_rollback":
        baseline_dev_nonce = join_config.baseline_dev_nonce or 100
        rollback_dev_nonce = join_config.rollback_dev_nonce or 99
        generator = RollbackDevNonceGenerator(
            baseline=baseline_dev_nonce,
            rollback=rollback_dev_nonce,
        )
        verifier = RollbackDevNonceVerifier()
        
    elif mode == "devnonce_memory_depth":
        count = join_config.count or 100
        replay_indices = join_config.replay_indices or [0, 9, 99]
        generator = MemoryDepthDevNonceGenerator(count=count)
        verifier = MemoryDepthVerifier(replay_indices=replay_indices)
        
    else:
        raise ValueError(f"Unknown join_replay mode: {mode}")
    
    return JoinReplayAttack(
        config=config,
        device=device,
        gateway=gateway,
        radio=radio,
        timing=join_config.timing,
        generator=generator,
        verifier=verifier,
        logger=logger,
        mode=mode,
        expected_behavior=expected,
    )


def _create_join_flood_attack(
    config: AttackConfig,
    device: Any,
    gateway: Any,
    logger: logging.Logger,
    radio: RadioMetadata,
    attack_config: dict[str, Any],
    expected: Any,
) -> JoinAbuseAttack:
    """Factory for JoinAbuseAttack (flood mode)."""
    flood_config = parse_join_flood_config(attack_config)
    
    return JoinAbuseAttack(
        config=config,
        device=device,
        gateway=gateway,
        logger=logger,
        radio=radio,
        mode="flood",
        flood_count=flood_config.flood_count,
        flood_interval_sec=flood_config.flood_interval_sec,
        virtual_devices=flood_config.virtual_devices,
        expected=expected,
    )


def _create_mac_abuse_attack(
    config: AttackConfig,
    device: Any,
    gateway: Any,
    logger: logging.Logger,
    radio: RadioMetadata,
    attack_config: dict[str, Any],
    expected: Any,
) -> MACCommandAbuse:
    """Factory for MACCommandAbuse."""
    mac_config = parse_mac_command_config(attack_config)
    malformation_type = mac_config.malformation_type or "truncated"
    
    return MACCommandAbuse(
        config=config,
        device=device,
        gateway=gateway,
        logger=logger,
        radio=radio,
        command_type=mac_config.command_type,
        malformed=mac_config.malformed,
        malformation_type=malformation_type,
        parameters=mac_config.parameters or {},
        expected=expected,
    )


def register_builtin_attacks() -> None:
    """Register all built-in attack plugins.
    
    This function must be called during app startup to populate
    the attack registry with built-in attack types.
    
    Raises:
        ValueError: If duplicate registration detected
    """
    logger.info("Registering built-in attack plugins...")
    
    # Uplink Replay Attack
    AttackRegistry.register(
        AttackSpec(
            name="uplink_replay",
            attack_class=UplinkReplayAttack,
            config_parser=parse_replay_config,
            factory=_create_replay_attack,  # Legacy factory (not used by new runner)
            aliases=[],
            description="Replay captured uplink frames to test frame counter validation",
        )
    )
    
    # Join Replay Attack (with multiple modes)
    AttackRegistry.register(
        AttackSpec(
            name="join_replay",
            attack_class=JoinReplayAttack,  # Primary class (though factory may use JoinAbuseAttack)
            config_parser=parse_join_replay_config,
            factory=_create_join_replay_attack,
            aliases=["replay", "duplicate_devnonce"],  # Legacy mode names
            description="Test DevNonce replay protection with various strategies",
        )
    )
    
    # Join Flood Attack
    AttackRegistry.register(
        AttackSpec(
            name="join_flood",
            attack_class=JoinAbuseAttack,
            config_parser=parse_join_flood_config,
            factory=_create_join_flood_attack,
            aliases=[],
            description="Flood Network Server with join requests",
        )
    )
    
    # MAC Command Injection/Abuse
    AttackRegistry.register(
        AttackSpec(
            name="mac_command_injection",
            attack_class=MACCommandAbuse,
            config_parser=parse_mac_command_config,
            factory=_create_mac_abuse_attack,
            aliases=["mac_malformed"],  # Both types use same implementation
            description="Inject legitimate or malformed MAC commands",
        )
    )
    
    logger.info(
        f"Registered {len(AttackRegistry.list_attacks())} attack types: "
        f"{', '.join(AttackRegistry.list_attacks())}"
    )
