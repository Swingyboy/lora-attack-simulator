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
  "schema_version": "1.0",
  "scenario_id": "join-replay-test",
  "attack": {
    "type": "join_devnonce",
    "config": {
      "valid_join_count": 50,
      "valid_devnonce_start": 0,
      "valid_devnonce_step": 1,
      "final_check": "replay_first",
      "result_cache_size": 10
    }
  }
}
```

**Modes:**
- `same_as_last`: Replay the last accepted DevNonce
- `lower_than_last`: Send a lower DevNonce than the last accepted one
- `replay_first`: Replay the first accepted DevNonce after N valid joins
- `custom`: Use an explicitly configured final DevNonce

### Uplink Replay Attack

Tests frame counter validation:

```json
{
  "attack": {
    "type": "uplink_replay",
    "replay_phase": {
      "count": 3,
      "delay_sec": 1.0
    }
  }
}
```

### MAC Command Abuse

Tests MAC command handling:

```json
{
  "attack": {
    "type": "mac_command_injection",
    "command_type": "LinkADRReq",
    "malformed": false,
    "parameters": {
      "data_rate": 5,
      "tx_power": 2
    }
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
        # Access typed configuration
        config = ctx.config
        
        # Use framework services
        ctx.gateway.start()
        ctx.logger.info("Starting custom attack")
        
        # Build and send attack traffic
        uplink = ctx.device.build_data_uplink(...)
        ctx.gateway.forward_uplink(uplink, ctx.radio)
        
        # Capture packets
        ctx.capture.capture_uplink(uplink, ...)
        
        # Stop gateway
        ctx.gateway.stop()
        
        # Return result
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
        aliases=[],
        description="Custom attack description",
    )
)
```

### 3. Create Scenario

```json
{
  "schema_version": "1.0",
  "attack": {
    "type": "custom_attack",
    "custom_param": "value"
  }
}
```

## Configuration

### Device Configuration

```json
{
  "device": {
    "dev_eui": "0123456789abcdef",
    "app_eui": "fedcba9876543210",
    "app_key": "00112233445566778899aabbccddeeff"
  }
}
```

### Target Configuration

```json
{
  "target": {
    "name": "chirpstack-local",
    "network_server": {
      "host": "127.0.0.1",
      "port": 1700
    }
  }
}
```

### Security Criteria

```json
{
  "expected_behavior": {
    "security_criteria": [
      {
        "criterion": "replayed_join_requests_with_same_devnonce_are_rejected",
        "description": "NS must reject duplicate DevNonce"
      }
    ],
    "secure_behavior": "reject_replayed_devnonce"
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
