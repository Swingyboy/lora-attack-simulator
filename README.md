# LoRaWAN Offensive Security Testing Framework

A protocol-level attack simulation framework for testing LoRaWAN Network Server implementations.

## Features

- **Interactive CLI** - Metasploit-like shell for managing attack scenarios
- **Protocol-Aware Attacks** - Replay, join abuse, MAC command manipulation
- **Semtech UDP Transport** - Compatible with standard LoRaWAN gateway forwarders
- **Session-Based Logging** - Structured JSONL logs with secret masking
- **JSON Scenarios** - Declarative attack definitions with expected behavior validation

## Installation

```bash
# Clone repository
git clone https://github.com/Swingyboy/lora-attack-simulator.git
cd lora-attack-simulator

# Create virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# Install package
pip install -e .
```

**Requirements:**
- Python 3.12+
- `cryptography==3.3.2`

## Quick Start

### Interactive Mode

```bash
lorawan-sim
```

Basic workflow:
```
# List available attack scenarios
show scenarios

# Load a scenario
use join-replay-v1

# View current configuration
show

# Modify parameters
set target.host 192.168.1.100
set target.port 1700

# Execute attack
run

# View results
# Results saved to: results/<session-id>/<scenario>.results.json
```

### Automation Mode

```bash
# Run scenario non-interactively
lorawan-sim use join-replay-v1 set target.host 192.168.1.100 run
```

## Available Attacks

### Replay Attacks
**Scenario:** `uplink-replay-v1`

Captures legitimate uplink packets and replays them to test FCnt validation.

**Tests:** Frame counter replay protection

### Join Procedure Abuse
**Scenario:** `join-replay-v1`

Replays JoinRequest messages with identical DevNonce values.

**Tests:** DevNonce validation, join procedure replay protection

### MAC Command Manipulation
**Scenario:** `mac-link-adr-v1`

Injects LinkADRReq commands to manipulate device parameters.

**Tests:** MAC command validation, ADR manipulation defenses

## Creating Attack Scenarios

Scenarios are JSON files in `examples/attacks/`:

```json
{
  "schema_version": "1.0",
  "scenario": {
    "title": "My Attack",
    "category": "replay"
  },
  "target": {
    "name": "test-ns",
    "transport": "semtech_udp",
    "host": "127.0.0.1",
    "port": 1700
  },
  "gateway": {
    "gateway_eui": "0102030405060708",
    "radio": {...}
  },
  "device": {
    "dev_eui": "0011223344556677",
    "activation": {...}
  },
  "attack": {
    "type": "replay",
    "config": {...}
  },
  "expected_behavior": {
    "should_reject_replay": true
  }
}
```

See `examples/attacks/` for complete examples.

## Logging

### Session Logs

All CLI activity is automatically logged to `logs/session-<timestamp>.log` in JSONL format.

### Log Levels

```bash
# In interactive mode
set logging.level debug

# Available: ERROR, WARNING, INFO, DEBUG, TRACE
```

### View Logging Configuration

```bash
show logging
```

**Features:**
- Dual output: terminal (colored) + file (JSONL)
- Automatic secret masking (AppKey, NwkSKey, AppSKey)
- Session-wide log files (one file per CLI session)
- TRACE level for protocol debugging

## Architecture

### Package Structure

```
src/
├── cli/                # Interactive shell
├── simulator/          # Runtime engine, session management
├── lorawan/            # Protocol implementation
│   ├── protocol/       # Frames, crypto, MAC commands
│   ├── device/         # Device simulator
│   ├── gateway/        # Gateway simulator
│   ├── scenario/       # Scenario schemas
│   └── semtech/        # Semtech UDP codec
├── attacks/            # Attack implementations
├── transport/          # UDP, in-memory transports
├── sim_logging/        # Logging subsystem
└── monitoring/         # ChirpStack integration

tests/                  # Unit and integration tests
examples/attacks/       # Attack scenario templates
```

### Key Components

- **Session** (`simulator/session.py`) - Tracks loaded scenario and runtime state
- **AttackRunner** (`attacks/runner.py`) - Orchestrates attack execution
- **TransportClient** (`transport/transport.py`) - Abstract transport interface
- **PacketCapture** (`attacks/packet_capture.py`) - Records attack traffic

## Development

### Running Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -q
```

### Test Structure

```
tests/
├── test_device_crypto_flow.py      # Device join/uplink flow
├── test_scenario_loader.py         # Scenario validation
├── attacks/
│   ├── test_replay.py              # Replay attack logic
│   ├── test_join_abuse.py          # Join abuse logic
│   └── test_mac_abuse.py           # MAC command abuse
└── protocol/
    └── test_mac_commands.py        # MAC command utilities
```

## Security Notice

**This framework is for authorized security testing only.**

- Only test Network Servers you own or have written permission to test
- Unauthorized LoRaWAN traffic may violate regulations (e.g., FCC Part 15, ETSI EN 300.220)
- The framework does not implement duty cycle restrictions
- Misuse may disrupt legitimate LoRaWAN networks

## License

MIT License - See LICENSE file for details

## References

- LoRaWAN 1.0.3 Specification
- Semtech UDP Packet Forwarder Protocol
- ChirpOTLE: A Framework for Practical LoRaWAN Security Evaluation
