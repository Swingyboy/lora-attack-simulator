# LoRAT (LoRa Attack Toolkit)

**A modular offensive-security testing framework for LoRaWAN Network Servers.**

LoRAT enables security researchers and network operators to validate LoRaWAN Network Server implementations against protocol-level attacks and abuse scenarios.

## Features

- **Attack Plugin Architecture**: Extensible attack system with typed configurations
- **Built-in Attack Library**: Join DevNonce validation, uplink replay, MAC command abuse
- **Interactive Shell**: Real-time attack execution with scenario management
- **Protocol Validation**: Test DevNonce handling, frame counter validation, MAC command processing
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

### 1. Interactive Shell Mode

```bash
lorat
```

```
LoRAT v0.2.0 - LoRa Attack Toolkit
Type 'help' for available commands.

lorat > load scenarios/join-devnonce-v1.json
✓ Loaded scenario: Join DevNonce Validation

lorat > set logging.level debug
✓ Log level changed to: DEBUG

lorat > run
🚀 Starting attack execution...
[INFO] Starting attack: join-rollback-v1
...
✓ Attack completed successfully

lorat > show results
Attack: join_devnonce
Status: SECURE
Message: NS correctly rejected invalid DevNonces
...
```

### 2. Command-Line Mode

```bash
# Run attack scenario
lorat run scenarios/join-devnonce-v1.json

# Validate scenario file
lorat validate scenarios/custom-attack.json

# Get help
lorat --help
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

### MAC Command Abuse

Tests MAC command handling:

```json
{
  "scenario": {
    "timeout_sec": 30
  },
  "attack": {
    "type": "mac_command_injection",
    "config": {
      "command_type": "LinkADRReq",
      "malformed": false,
      "parameters": {
        "data_rate": 5,
        "tx_power": 2
      }
    }
  },
  "expected": {
    "profile": "lorawan_mac_command_validation"
  }
}
```

## Writing Custom Attacks

LoRAT uses a plugin architecture. Create a new attack in 3 steps:

### 1. Create Attack Class

```python
from lora_attack_toolkit.attacks.base import BaseAttack
from lora_attack_toolkit.attacks.result import AttackResult

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
            success=True,
            message="Attack completed",
            metrics={},
        )
```

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
    "timeout_sec": 30
  },
  "attack": {
    "type": "custom_attack",
    "config": {
      "custom_param": "value"
    }
  },
  "expected": {
    "profile": "lorawan_1_0_3_devnonce_validation"
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
| `lorawan_mac_command_validation` | MAC command syntax and ADR state validation |

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
├── app/                 # CLI and shell interface
│   ├── cli.py
│   ├── runner.py
│   └── shell.py
├── attacks/            # Attack plugin system
│   ├── base.py         # BaseAttack interface
│   ├── context.py      # AttackContext
│   ├── registry.py     # AttackRegistry
│   └── builtin/        # Built-in attacks
├── core/               # Configuration and schemas
├── lorawan/            # LoRaWAN protocol implementation
├── device/             # Device simulation
├── gateway/            # Gateway simulation
├── transport/          # Network transport
└── metrics/            # Metrics and analysis
```

## Architecture

LoRAT follows SOLID principles:

- **Single Responsibility**: Attacks own attack logic, Runner owns orchestration
- **Open/Closed**: Add new attacks without modifying core framework
- **Liskov Substitution**: All attacks implement `BaseAttack.run(ctx)`
- **Interface Segregation**: `AttackContext` exposes only necessary services
- **Dependency Inversion**: Attacks depend on abstractions, not framework internals

## Requirements

- Python 3.10+
- Virtual environment recommended
- No external LoRaWAN server required for testing (uses built-in simulators)

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
