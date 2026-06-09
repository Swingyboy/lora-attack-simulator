"""Backward-compat re-export. Use lora_attack_toolkit.config instead."""
from lora_attack_toolkit.config import (  # noqa: F401
    TargetConfig, RadioConfig, GatewayConfigV1, ScenarioMeta,
    ExpectedBehavior, AttackTiming, ReplayPhaseConfig, CapturePhaseConfig,
    ReplayConfigV1, JoinDevNonceConfigV1, MACCommandConfigV1,
    AttackConfigV1, AttackScenarioV1,
    parse_replay_config, parse_join_devnonce_config, parse_mac_command_config,
    DeviceConfig, LoggingConfig,
)

# Legacy alias
AttackScenarioConfig = AttackScenarioV1
