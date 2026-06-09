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

---

## Available Examples

### join-devnonce-v1.json
- **Attack type**: `join_devnonce`
- **Validation profile**: `lorawan_1_0_3_devnonce_validation`
- **Description**: Validates DevNonce replay and rollback protection.  
  Sends N valid JoinRequests then attempts a disallowed final DevNonce.

### uplink-replay-v1.json
- **Attack type**: `uplink_replay`
- **Validation profile**: `lorawan_uplink_replay_protection`
- **Description**: Captures a legitimate uplink then replays it to test frame counter validation.

### mac-link-adr-v1.json
- **Attack type**: `mac_command_injection`
- **Validation profile**: `lorawan_mac_command_validation`
- **Description**: Injects a LinkADRReq MAC command to test ADR parameter handling.

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
| `lorawan_1_0_3_devnonce_validation` | NS must reject reused or rolled-back DevNonces |
| `lorawan_uplink_replay_protection` | NS must reject replayed uplinks with same FCnt |
| `lorawan_mac_command_validation` | NS must validate MAC command parameters safely |
