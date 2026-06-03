# Attack Scenario Expected Behavior Validation Guide

## Overview

Phase 4 of the Attack Scenario Format v1.0 introduces **automated security posture validation**. Analyzers now compare attack results against predefined `success_criteria` to assess whether the Network Server (NS) exhibits secure behavior.

## How It Works

1. **Scenario Definition**: Add `expected` block to v1.0 attack scenarios
2. **Attack Execution**: Runner passes `expected` to attack instance
3. **Analysis**: Analyzer evaluates results against `success_criteria`
4. **Validation**: Validation module checks each criterion and generates report
5. **Results**: Attack results include validation summary and per-criterion status

## Expected Behavior Schema

```json
{
  "expected": {
    "secure_behavior": "ns_rejects_replayed_uplinks_with_same_fcnt",
    "success_criteria": [
      "first_uplink_is_sent",
      "replayed_uplinks_with_same_fcnt_are_rejected",
      "ns_maintains_fcnt_validation"
    ]
  }
}
```

### Fields

- **`secure_behavior`** (string): Human-readable description of expected secure NS behavior
- **`success_criteria`** (list[str]): List of criterion identifiers that must pass for NS to be considered secure

## Supported Criteria by Attack Type

### Uplink Replay Attack

**Attack Type**: `uplink_replay`, `replay`

**Criteria**:
- `first_uplink_is_sent` - Original uplink was captured
- `replayed_uplinks_with_same_fcnt_are_rejected` - NS rejected replay packets
- `replay_attack_is_blocked` - Replay not accepted by NS
- `ns_maintains_fcnt_validation` - FCnt validation working correctly

### Join Replay Attack

**Attack Type**: `join_replay`, `join_abuse` (replay mode)

**Criteria**:
- `first_join_request_is_accepted` - Initial join succeeded
- `replayed_join_requests_with_same_devnonce_are_rejected` - DevNonce validation working
- `ns_maintains_devnonce_history` - DevNonce tracking in place

### Join Flood Attack

**Attack Type**: `join_flood`, `join_abuse` (flood mode)

**Criteria**:
- `first_join_request_is_accepted` - Initial join succeeded (baseline)
- `join_flooding_is_rate_limited` - Rate limiting detected
- `ns_rejects_excessive_join_requests` - Flood protection active

### MAC Command Injection

**Attack Type**: `mac_command_injection`, `mac_abuse`

**Criteria**:
- `ns_validates_mac_command_syntax` - Malformed commands rejected
- `ns_rejects_out_of_spec_parameters` - Invalid parameters rejected
- `ns_ignores_malicious_adr_manipulation` - ADR not manipulated
- `ns_maintains_secure_adr_state` - ADR state remains secure

## Examples in Repository

- `examples/attacks/v1/uplink-replay-v1.json` - Replay validation
- `examples/attacks/v1/join-replay-v1.json` - DevNonce validation
- `examples/attacks/v1/mac-link-adr-v1.json` - MAC command validation

## References

- **Schema**: `src/lorawan_sim/domain/attack_scenario/schema_v1.py:70-79`
- **Validation Logic**: `src/lorawan_sim/attacks/validation.py`
- **Analyzer Updates**: `src/lorawan_sim/attacks/analyzer.py`, `replay.py`, `join_abuse.py`, `mac_abuse.py`
- **Runner Integration**: `src/lorawan_sim/attacks/runner.py:_run_v1()`, `_create_attack_v1()`
- **Base Attack**: `src/lorawan_sim/attacks/base.py:run()`

---

**Version**: 1.0  
**Last Updated**: Phase 4 Implementation  
**Status**: Experimental - feedback welcome
