# Attack Scenario Format v1.0 Examples

This directory contains example attack scenarios using the **v1.0 unified format** introduced in Phase 1 of the scenario format migration.

## Format Differences from v0.9

### Structural Changes

1. **Schema Version Field**: All v1.0 scenarios include `"schema_version": "1.0"` at the top level
2. **Unified Attack Config**: Attack-specific config nested under `attack.config` instead of top-level blocks
3. **Target Abstraction**: Network Server connection separated from gateway via `target` section
4. **Expected Behavior**: New `expected` section defines security testing criteria

### Example Comparison

**v0.9 format** (legacy):
```json
{
  "scenario": {...},
  "gateway": {...},
  "device": {...},
  "join_abuse": {           // Attack-specific top-level block
    "mode": "replay",
    "replay_count": 1
  },
  "logging": {...}
}
```

**v1.0 format** (new):
```json
{
  "schema_version": "1.0",  // Version indicator
  "scenario": {
    "id": "...",
    "title": "...",
    "category": "join_abuse",
    "type": "join_replay"
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
    "type": "join_replay",
    "config": {             // Nested config
      "mode": "replay",
      "replay_count": 1
    }
  },
  "expected": {             // NEW: Security criteria
    "secure_behavior": "ns_rejects_duplicate_devnonce",
    "success_criteria": [...]
  },
  "logging": {...}
}
```

## Available Examples

### join-replay-v1.json
- **Category**: `join_abuse`
- **Type**: `join_replay`
- **Description**: Tests Network Server DevNonce validation by replaying JoinRequests
- **Expected**: NS should reject replayed joins with duplicate DevNonce

### uplink-replay-v1.json
- **Category**: `replay`
- **Type**: `uplink_replay`
- **Description**: Tests uplink replay protection by replaying data frames
- **Expected**: NS should reject replayed uplinks with same FCnt

## Backward Compatibility

The loader supports both v0.9 and v1.0 formats during the migration period:
- **No schema_version field** → Detected as v0.9 (legacy)
- **schema_version: "1.0"** → Parsed with v1.0 schema

All existing v0.9 scenarios in `examples/attacks/*.json` continue to work.

## Running v1.0 Scenarios

```bash
# Validate v1.0 scenario
lorawan-sim validate-attack examples/attacks/v1/join-replay-v1.json

# Run v1.0 attack (Phase 2 required)
# lorawan-sim run-attack examples/attacks/v1/join-replay-v1.json
```

⚠️ **Note**: Attack runner (`run-attack`) does not yet support v1.0 format. This will be implemented in Phase 2 of the migration.

## Migration Status

- ✅ **Phase 1**: Schema and dual-format loader complete
- ⏳ **Phase 2**: Runner support and attack config migration
- ⏳ **Phase 3**: Target abstraction and naming consistency
- ⏳ **Phase 4**: Expected behavior validation
- ⏳ **Phase 5**: Full migration and v0.9 deprecation

See `Attack_Scenario_Format_Specification.md` (project root) for full specification and `~/.copilot/session-state/.../files/scenario_format_analysis.md` for implementation plan.
