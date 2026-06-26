# Attack Scenario Examples

This directory contains ready-to-run attack scenarios for LoRAT.

## Scenario Format

A scenario file describes everything needed to execute one attack:

```json
{
  "scenario": {
    "description": "Human-readable description (optional)",
    "timeout_sec": 30.0
  },
  "target": {
    "name": "chirpstack-local",
    "transport": "semtech_udp",
    "host": "127.0.0.1",
    "port": 1700
  },
  "gateway": {
    "gateway_eui": "0102030405060708",
    "pull_data_interval_sec": 5,
    "radio": {
      "region": "EU868",
      "frequency_hz": 868100000,
      "data_rate": "SF7BW125",
      "rssi": -60,
      "snr": 7.5
    }
  },
  "device": {
    "name": "test-device",
    "lorawan_version": "1.0.3",
    "region": "EU868",
    "class": "A",
    "activation": {
      "mode": "OTAA",
      "dev_eui": "0011223344556677",
      "join_eui": "0011223344556677",
      "app_key": "00112233445566770011223344556677"
    }
  },
  "attack": {
    "type": "<attack_type>",
    "config": { ... }
  },
  "expected": {
    "profile": "<validation_profile>"
  },
  "logging": {
    "level": "INFO",
    "log_phy_payload": true,
    "log_semtech_udp": true
  }
}
```

**`scenario.timeout_sec`** is the only pacing parameter.
It controls the wait interval between consecutive messages (JoinRequest→JoinRequest, JoinAccept→Uplink, Uplink→Uplink).

Attack metadata (id, title, category) is resolved internally from the registry — it does not belong in the scenario file.

**`expected` is optional for `join_devnonce` scenarios.** When omitted, the profile is derived
from `device.lorawan_version` (e.g. `lorawan_1_0_4_devnonce_validation` for version `1.0.4`).
The `device.lorawan_version` field is the single knob that controls the interpretation:
- `1.0.4` or `1.1` → accepting a lower DevNonce is **VULNERABLE** (monotonic-DevNonce compliance)
- `1.0.3` → the same observation is **INCONCLUSIVE** (capability detection only)

---

## Available Examples

### join-devnonce-v1.json
- **Attack type**: `join_devnonce`
- **Default mode**: `target_lorawan_1_0_4: false`, `device.lorawan_version: 1.0.3` — accepting a lower DevNonce is reported as **INCONCLUSIVE** (capability detection only)
- **Validation profile**: `lorawan_1_0_3_devnonce_validation`
- **Description**: Validates DevNonce handling: replay, lower-than-last, retention, and 1.0.4
  monotonic compliance. The verdict mode is selected at runtime via `attack.config`:

  **LoRaWAN 1.0.3 baseline** (capability — INCONCLUSIVE if lower DevNonce accepted):
  ```
  use join-devnonce-v1
  set target.host 192.168.1.10
  run
  ```

  **LoRaWAN 1.0.4 monotonic compliance** (same probe — VULNERABLE if lower DevNonce accepted):
  ```
  use join-devnonce-v1
  set target.host 192.168.1.10
  set attack.config.target_lorawan_1_0_4 true
  run
  ```

  **Replay variant** (check that NS rejects a previously-seen DevNonce):
  ```
  set attack.config.final_check replay_first
  ```

### uplink-replay-v1.json
- **Attack type**: `uplink_replay`
- **Validation profile**: `lorawan_uplink_replay_protection`
- **Description**: Captures a legitimate uplink then replays it to test frame counter validation.

### uplink-forgery-v1.json
- **Attack type**: `uplink_forgery`
- **Validation profile**: `lorawan_uplink_replay_protection`
- **Description**: Sends forged uplink frames with manipulated MIC, FCnt, or DevAddr
  to probe how the Network Server validates frame integrity.

---

## Running Scenarios

### Interactive mode (recommended)

```bash
lorat
lorat > use join-devnonce-v1
lorat > set target.host 192.168.1.10
lorat > run
```

### Module invocation

```bash
python -m lora_attack_toolkit.main
```

---

## Validation Profiles

| Profile | Description |
|---------|-------------|
| `lorawan_1_0_3_devnonce_validation` | NS must reject a reused DevNonce (LoRaWAN 1.0.3 replay protection); lower DevNonce accepted → INCONCLUSIVE |
| `lorawan_1_0_4_devnonce_validation` | NS must reject a DevNonce ≤ last accepted (LoRaWAN 1.0.4 monotonic rule); accepting a lower DevNonce → VULNERABLE |
| `lorawan_1_1_devnonce_validation` | Same as 1.0.4 — monotonic-DevNonce compliance required; accepting a lower DevNonce → VULNERABLE |
| `lorawan_uplink_replay_protection` | NS must reject replayed uplinks with same FCnt |

> **MAC command validation** was designed but not shipped. A `lorawan_mac_command_validation`
> profile exists in the codebase for experimental use only — the `mac_command_injection` attack
> is not registered and has no production example scenario.
