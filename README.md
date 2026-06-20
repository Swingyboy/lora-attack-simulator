# LoRAT (LoRa Attack Toolkit)

**A modular offensive-security testing framework for LoRaWAN Network Servers.**

LoRAT enables security researchers and network operators to validate LoRaWAN Network Server implementations against protocol-level attacks and abuse scenarios.

> **Scope.** LoRAT is a focused research prototype for security testing of
> LoRaWAN Network Servers using Class A, OTAA, EU868, LoRaWAN 1.0.3, and the
> Semtech UDP Packet Forwarder protocol.

## Features

- **Attack Plugin Architecture**: Extensible attack system with typed configurations
- **Built-in Attack Library**: Join DevNonce validation, uplink replay, and uplink forgery
- **Interactive Shell**: Real-time attack execution with scenario management
- **Protocol Validation**: Test DevNonce handling, frame counter validation, and MIC verification
- **Comprehensive Logging**: Structured logs with attack traces and metrics
- **Type-Safe Configuration**: JSON schemas with typed Python models

## Installation

```bash
# Clone repository
git clone https://github.com/Swingyboy/lora-attack-simulator.git
cd lora-attack-simulator

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install -e .

# Verify installation
lorat --help
```

## Quick Start

### 1. Interactive Mode

```bash
lorat
```

```
lorat > show scenarios
lorat > use join-devnonce-v1
lorat > set target.host 192.168.1.10
lorat > show options
lorat > run
```

### 2. Single Command Mode

```bash
# Execute one console command and exit
lorat "use join-devnonce-v1"
```

## Attack Types

### Join DevNonce Validation

Tests DevNonce replay protection:

```json
{
  "scenario": {
    "timeout_sec": 30
  },
  "attack": {
    "type": "join_devnonce",
    "config": {
      "valid_join_count": 50,
      "valid_devnonce_start": 0,
      "valid_devnonce_step": 1,
      "final_check": "replay_first",
      "result_cache_size": 10
    }
  },
  "expected": {
    "profile": "lorawan_1_0_3_devnonce_validation"
  }
}
```

**Modes (`final_check`):**
- `same_as_last`: Replay the last accepted DevNonce
- `lower_than_last`: Send a lower DevNonce than the last accepted one
- `replay_first`: Replay the first accepted DevNonce after N valid joins
- `custom`: Use an explicitly configured final DevNonce

**Optional timing override** (`attack.config.timing`):

```json
{
  "attack": {
    "config": {
      "timing": {
        "join_accept_timeout_sec": 7.0
      }
    }
  }
}
```

`join_accept_timeout_sec` controls how long to wait for a JoinAccept before
considering the attempt failed. RX1/RX2 window values follow LoRaWAN 1.0.3
defaults and are not user-configurable.

### Uplink Replay Attack

Tests frame counter validation:

```json
{
  "scenario": {
    "timeout_sec": 30
  },
  "attack": {
    "type": "uplink_replay",
    "config": {
      "capture_phase": {
        "perform_join": true,
        "send_baseline_uplink": true,
        "payload_hex": "01020304"
      },
      "replay_phase": {
        "mode": "immediate",
        "count": 3,
        "delay_sec": 0.1
      },
      "fcnt_strategy": "reuse_original",
      "mic_strategy": "reuse_original"
    }
  },
  "expected": {
    "profile": "lorawan_uplink_replay_protection"
  }
}
```

### MAC Command Abuse (designed, not shipped)

> **Not part of the shipped attack set.** A MAC-command abuse attack was designed
> but excluded because, within the current scope (simulated device + Network
> Server under test over Semtech UDP), it could not demonstrate a valid threat
> model: it never transmits an authenticated frame nor validates a target
> response. The prototype implementation is retained under
> `lora_attack_toolkit.experimental` for documentation and future work only.

## Writing Custom Attacks

LoRAT uses a plugin architecture. Create a new attack in 3 steps:

### 1. Create Attack Class

```python
from lora_attack_toolkit.attacks.base import BaseAttack
from lora_attack_toolkit.attacks.result import (
    AttackResult,
    Confidence,
    ExecutionStatus,
    SecurityVerdict,
)

class CustomAttack(BaseAttack):
    name = "custom_attack"

    def run(self, ctx):
        """Execute attack using context services."""
        config = ctx.config

        ctx.gateway.start()
        ctx.logger.info("Starting custom attack")

        uplink = ctx.device.build_data_uplink(...)
        ctx.gateway.forward_uplink(uplink, ctx.radio)
        ctx.capture.capture_uplink(uplink, ...)

        ctx.gateway.stop()

        return AttackResult(
            attack_name=self.name,
            attack_type="custom",
            message="Attack completed",
            execution_status=ExecutionStatus.COMPLETED,
            security_verdict=SecurityVerdict.INCONCLUSIVE,
            confidence=Confidence.LOW,
            metrics={},
        )
```

> `AttackResult` reports an `execution_status` (did the attack run?) and a
> `security_verdict` (`SECURE` / `VULNERABLE` / `INCONCLUSIVE`) with a
> `confidence`. There is no boolean `success` field — absent or unattributable
> evidence must be reported as `INCONCLUSIVE`, never coerced to a pass/fail.

### 2. Register Attack

```python
from lora_attack_toolkit.attacks.registry import AttackRegistry, AttackSpec

AttackRegistry.register(
    AttackSpec(
        name="custom_attack",
        attack_class=CustomAttack,
        config_parser=parse_custom_config,
        title="Custom Attack",
        category="custom",
        description="Custom attack description",
    )
)
```

### 3. Create Scenario

```json
{
  "scenario": {
    "description": "Custom attack scenario",
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
    "type": "custom_attack",
    "config": {
      "custom_param": "value"
    }
  },
  "expected": {
    "profile": "lorawan_1_0_3_devnonce_validation"
  },
  "logging": {
    "level": "INFO",
    "log_phy_payload": true,
    "log_semtech_udp": true
  }
}
```

## Configuration

### Scenario Parameters

| Field | Type | Description |
|-------|------|-------------|
| `scenario.timeout_sec` | float | Inter-message pacing interval in seconds (default: 30.0) |
| `scenario.description` | string | Optional human-readable description |

`timeout_sec` controls the wait interval between consecutive messages:
- JoinRequest → JoinRequest
- JoinRequest → Uplink
- Uplink → Uplink

### Validation Profiles

The `expected.profile` field selects a named security validation profile.
Built-in profiles:

| Profile | Description |
|---------|-------------|
| `lorawan_1_0_3_devnonce_validation` | LoRaWAN 1.0.3 DevNonce replay protection |
| `lorawan_uplink_replay_protection` | Uplink frame counter replay protection |
| `lorawan_uplink_forgery_protection` | Uplink MIC / FCnt / DevAddr forgery rejection |

> The `lorawan_mac_command_validation` profile exists only for the experimental,
> unregistered MAC-command attack (see *MAC Command Abuse — designed, not
> shipped*) and is not part of the shipped attack set.

### Device Configuration

```json
{
  "device": {
    "name": "test-device",
    "lorawan_version": "1.0.3",
    "region": "EU868",
    "class": "A",
    "activation": {
      "mode": "OTAA",
      "dev_eui": "0123456789abcdef",
      "join_eui": "fedcba9876543210",
      "app_key": "00112233445566778899aabbccddeeff"
    }
  }
}
```

### Target Configuration

```json
{
  "target": {
    "name": "chirpstack-local",
    "transport": "semtech_udp",
    "host": "127.0.0.1",
    "port": 1700
  }
}
```

## Testing

```bash
# Run all tests
.venv/bin/python -m pytest -q

# Run specific test module
.venv/bin/python -m pytest tests/attacks/ -v

# Run with coverage
.venv/bin/python -m pytest --cov=lora_attack_toolkit
```

## Project Structure

```
src/lora_attack_toolkit/
├── main.py              # Entry point: argparse, bootstrap, session, logging
├── runner.py            # Attack scenario runner
├── config.py            # All configuration types and scenario loader
├── app/
│   ├── console.py       # Interactive command loop (LoRaWANConsole)
│   └── params.py        # Parameter metadata for autocomplete/help
├── attacks/             # Attack plugin system
│   ├── base.py          # BaseAttack interface
│   ├── context.py       # AttackContext
│   ├── registry.py      # AttackRegistry + AttackSpec
│   └── builtin/         # Built-in attack implementations
├── lorawan/             # LoRaWAN protocol implementation
│   ├── radio.py         # Radio abstraction (channels, CFList, duty-cycle)
│   ├── frames.py        # PHY frame building and parsing
│   ├── crypto.py        # AES-CMAC, session key derivation
│   ├── mac_commands.py  # MAC command types and parsing
│   ├── join.py          # OTAA join lifecycle helpers
│   └── semtech_udp.py   # Semtech UDP packet encoding/decoding
├── runtime/             # Runtime simulation objects
│   ├── device.py        # SimulatedDevice + DeviceRuntime + create_device()
│   ├── gateway.py       # GatewaySimulator + create_gateway()
│   └── session.py       # CLI session state
└── transport/           # Network transport layer
    ├── udp.py           # UDP socket transport
    ├── resilient.py     # Retry + reconnect wrapper
    └── errors.py        # Transport exception hierarchy
```

## Architecture

LoRAT follows SOLID principles:

- **Single Responsibility**: Attacks own attack logic, Runner owns orchestration
- **Open/Closed**: Add new attacks without modifying core framework
- **Liskov Substitution**: All attacks implement `BaseAttack.run(ctx)`
- **Interface Segregation**: `AttackContext` exposes only necessary services
- **Dependency Inversion**: Attacks depend on abstractions, not framework internals

## Requirements

- Python 3.12+
- Virtual environment recommended
- No external LoRaWAN server required for testing (uses built-in simulators)

## Known Limitations

LoRAT is a research prototype with a deliberately frozen scope:

- **Transports**: Semtech UDP Packet Forwarder only (MQTT / WebSocket not implemented). The transport is a limited packet forwarder simulator.
- **Region**: EU868 only.
- **Device class**: Class A only.
- **Activation**: OTAA only (ABP not supported).
- **LoRaWAN version**: 1.0.3 only.
- **Attacks**: `join_devnonce`, `uplink_replay`, `uplink_forgery`. The MAC-command abuse attack is designed but not shipped (kept under `lora_attack_toolkit.experimental`, unregistered).

Scenarios outside this scope (e.g. `region: US915`, `class: C`, ABP activation) are rejected at config-parse time with an explicit error.

## License

MIT License

## Contributing

Contributions welcome! Please:

1. Follow existing code style
2. Add tests for new features
3. Update documentation
4. Ensure `pytest` passes

## Disclaimer

LoRAT is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any LoRaWAN Network Server.

## References

- [LoRaWAN Specification](https://lora-alliance.org/resource_hub/lorawan-specification-v1-0-3/)
- [LoRaWAN Security Whitepaper](https://lora-alliance.org/resource_hub/lorawan-security-whitepaper/)

---

**Version**: 0.2.0
**Status**: Active Development
**Maintainer**: [@Swingyboy](https://github.com/Swingyboy)
