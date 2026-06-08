# Attack Scenario Format v1.0 Examples

This directory contains example attack scenarios using the **v1.0 unified format** introduced in Phase 1 of the scenario format migration.

## Format Differences from v0.9

### Structural Changes

1. **Schema Version Field**: All v1.0 scenarios include `"schema_version": "1.0"` at the top level
2. **Unified Attack Config**: Attack-specific config nested under `attack.config` instead of top-level blocks
3. **Target Abstraction**: Network Server connection separated from gateway via `target` section
4. **Expected Behavior**: New `expected` section defines security testing criteria

### Example Comparison

**v1.0 format** (new):
```json
{
  "schema_version": "1.0",  // Version indicator
  "scenario": {
    "id": "...",
    "title": "...",
    "category": "join_devnonce",
    "type": "join_devnonce"
  },
  "target": {               // NEW: NS connection abstraction
    "name": "chirpstack-local",
    "transport": "semtech_udp",
    "host": "127.0.0.1",
    "port": 1700
  },
  "gateway": {...},
  "device": {...},
  "attack": {               // Unified attack section
    "type": "join_devnonce",
    "config": {             // Nested config
      "valid_join_count": 1,
      "final_check": "same_as_last"
    }
  },
  "expected": {             // NEW: Security criteria
    "secure_behavior": "ns_rejects_invalid_devnonce",
    "success_criteria": [...]
  },
  "logging": {...}
}
```

## Available Examples

### join-devnonce-v1.json
- **Category**: `join_devnonce`
- **Type**: `join_devnonce`
- **Description**: Tests Network Server DevNonce validation through replay, rollback, and retention checks
- **Expected**: NS should reject invalid or reused DevNonce values

### uplink-replay-v1.json
- **Category**: `replay`
- **Type**: `uplink_replay`
- **Description**: Tests uplink replay protection by replaying data frames
- **Expected**: NS should reject replayed uplinks with same FCnt

### mac-link-adr-v1.json
- **Category**: `mac_abuse`
- **Type**: `mac_command_injection`
- **Description**: Tests MAC command handling with LinkADRReq injection
- **Expected**: NS should validate and safely apply ADR parameters

## Running v1.0 Scenarios

```bash
# Interactive mode
python -m lora_attack_toolkit.app.cli
# Then: use join-devnonce-v1

# Command-line mode
python -m lora_attack_toolkit.app.cli use join-devnonce-v1 run

# After pip install -e .
lorat use join-devnonce-v1 run
```

✅ **Complete**: Attack Plugin API with registry-based dispatch.

## Migration Status

- ✅ **Plugin Architecture**: Registry-based attack system complete
- ✅ **Directory Structure**: Organized modular package layout
- ✅ **Project Rename**: LoRAT (LoRa Attack Toolkit)
- ✅ **Security Criteria**: Renamed from success_criteria

See `Attack_Scenario_Format_Specification.md` (project root) for full specification and `~/.copilot/session-state/.../files/scenario_format_analysis.md` for implementation plan.
