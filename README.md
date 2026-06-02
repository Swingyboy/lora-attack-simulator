# LoRaWAN Attack Simulator

**Clean-room LoRaWAN Network Server offensive-security testing framework**

A protocol-level attack simulator for testing LoRaWAN 1.0.3 Network Server implementations via Semtech UDP gateway communication. Implements replay attacks, join procedure abuse, and MAC command manipulation for security testing and vulnerability analysis.

## Key Features

**Core Capabilities:**
- ✅ OTAA join workflow (LoRaWAN 1.0.3)
- ✅ Periodic unconfirmed uplink generation
- ✅ Semtech UDP gateway packet-forwarder emulation
- ✅ Structured JSON logging
- ✅ Scenario validation + execution via CLI

**Attack Framework (Phases 1-4 Complete):**
- ✅ **Replay attacks**: Immediate, delayed, and burst replay variants with FCnt analysis
- ✅ **Join procedure abuse**: DevNonce replay and join flooding with rate limit detection
- ✅ **MAC command abuse**: Legitimate and malformed command injection with ADR tracking
- ✅ Packet capture and post-attack analysis
- ✅ 49 unit tests (all passing)
- ✅ 10 example attack scenarios

## Project Structure

```text
src/lorawan_sim/
  app/                     # CLI entrypoints
  core/                    # Contracts and scenario runner
  domain/
    device/                # Device state/model/factory
    gateway/               # Gateway state/model/factory
    scenario/              # Scenario schema and loader
    strategy/              # Uplink scheduling strategies
    attack_scenario/       # Attack scenario schema and loader
  protocol/
    lorawan/               # LoRaWAN frame, crypto, and MAC commands
    semtech/               # Semtech UDP packet codec
  adapters/
    transport/             # UDP and in-memory transport adapters
  attacks/                 # Attack implementations
    base.py              # Base attack class and interfaces
    replay.py            # Replay attack variants
    join_abuse.py        # Join procedure abuse (replay/flood)
    mac_abuse.py         # MAC command manipulation
    packet_capture.py    # Packet capture utilities
    analyzer.py          # Post-attack analysis
  observability/
    logging/               # JSON logger configuration
  tests/                   # Unit tests (49 tests, all passing)
    attacks/             # Attack framework tests
    protocol/            # Protocol utility tests
```

## Quick Start

### Installation

```bash
# Clone repository
git clone <repository-url>
cd attack-simulator

# Create virtual environment and install
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .

# Verify installation
lorawan-sim --help
```

### Basic Usage

```bash
# Validate a standard scenario
lorawan-sim validate examples/debug-join-uplink.json

# Run a standard scenario
lorawan-sim run examples/debug-join-uplink.json

# Validate an attack scenario
lorawan-sim validate-attack examples/attacks/replay-immediate.json

# Run an attack scenario (implementation in progress)
lorawan-sim run-attack examples/attacks/replay-immediate.json
```

## Attack Framework

The simulator implements three categories of LoRaWAN security tests:

### 1. Replay Attacks

Test Network Server replay protection mechanisms by capturing and replaying uplink packets.

**Variants:**
- **Immediate**: Replay within 1-2 seconds
- **Delayed**: Replay after 10+ seconds
- **Burst**: Replay same packet multiple times

**Test Objectives:**
- Verify NS rejects replayed packets
- Validate FCnt window handling
- Detect replay protection vulnerabilities

**Example Scenarios:**
```bash
lorawan-sim validate-attack examples/attacks/replay-immediate.json
lorawan-sim validate-attack examples/attacks/replay-delayed.json
lorawan-sim validate-attack examples/attacks/replay-burst.json
```

### 2. Join Procedure Abuse

Test Network Server join validation and rate limiting with DevNonce replay and join flooding.

**Modes:**
- **Replay**: Replay JoinRequest with same DevNonce
- **Flood**: Generate multiple JoinRequests from virtual devices

**Test Objectives:**
- Verify NS rejects DevNonce reuse
- Test join request rate limiting
- Detect join flooding vulnerabilities (DoS)

**Example Scenarios:**
```bash
lorawan-sim validate-attack examples/attacks/join-replay.json
lorawan-sim validate-attack examples/attacks/join-flood-small.json  # 10 joins, 3 devices
lorawan-sim validate-attack examples/attacks/join-flood-large.json  # 100 joins, 10 devices
```

### 3. MAC Command Abuse

Test Network Server MAC command parsing and validation with legitimate and malformed commands.

**Command Types:**
- LinkADRReq (ADR manipulation)
- RXParamSetupReq (RX window configuration)
- NewChannelReq (channel definition)
- DevStatusReq, DutyCycleReq, RXTimingSetupReq

**Malformation Types:**
- Truncated (incomplete payloads)
- Oversized (extra bytes)
- Invalid values (out-of-spec parameters)
- Corrupted (random bytes)

**Test Objectives:**
- Verify NS accepts valid MAC commands
- Test NS robustness against malformed commands
- Validate ADR state tracking
- Detect parser vulnerabilities

**Example Scenarios:**
```bash
lorawan-sim validate-attack examples/attacks/mac-link-adr.json
lorawan-sim validate-attack examples/attacks/mac-rx-param-setup.json
lorawan-sim validate-attack examples/attacks/mac-malformed-truncated.json
lorawan-sim validate-attack examples/attacks/mac-malformed-invalid.json
```

## Development

### Running Tests

```bash
# Run all tests (49 tests)
PYTHONPATH=src python -m unittest discover -s src/lorawan_sim/tests -q

# Run specific test module
PYTHONPATH=src python -m unittest src/lorawan_sim/tests.attacks.test_replay
PYTHONPATH=src python -m unittest src/lorawan_sim/tests.attacks.test_join_abuse
PYTHONPATH=src python -m unittest src/lorawan_sim/tests.attacks.test_mac_abuse
PYTHONPATH=src python -m unittest src/lorawan_sim/tests.protocol.test_mac_commands

# Run with verbose output
PYTHONPATH=src python -m unittest discover -s src/lorawan_sim/tests -v
```

### Test Coverage

- **Total Tests:** 49 (all passing ✅)
- Core framework: 7 tests
- Phase 2 (Replay): 5 tests
- Phase 3 (Join Abuse): 11 tests
- Phase 4 (MAC Abuse): 27 tests

### Project Status

**Completed Phases (4/5):**
- ✅ Phase 1: Core Attack Infrastructure
- ✅ Phase 2: Replay Attack Implementation
- ✅ Phase 3: Join Procedure Abuse
- ✅ Phase 4: MAC Command Abuse
- 🚧 Phase 5: Integration and Documentation (in progress)

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for detailed roadmap.

## Documentation

- **[ATTACK_GUIDE.md](ATTACK_GUIDE.md)** - Comprehensive execution guide with troubleshooting
- **[SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md)** - Vulnerability taxonomy and detection strategies
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design and module structure
- **[ATTACK_SCENARIOS.md](ATTACK_SCENARIOS.md)** - Attack theory and implementation details
- **[PHASE3_SUMMARY.md](PHASE3_SUMMARY.md)** - Join abuse implementation details
- **[PHASE4_SUMMARY.md](PHASE4_SUMMARY.md)** - MAC command abuse implementation details
- **[TEST_BREAKDOWN.md](TEST_BREAKDOWN.md)** - Test suite overview

## Architecture Highlights

### Design Principles

1. **Clean-room implementation**: No code reuse from other LoRaWAN projects
2. **Protocol separation**: LoRaWAN logic isolated from transport layer
3. **Pluggable transports**: UDP and in-memory implementations
4. **Scenario-driven**: JSON configuration for all scenarios
5. **Attack framework**: Reusable base classes for attack implementation

### Attack Lifecycle

All attacks follow a consistent pattern:

```python
class AttackExample(BaseAttack):
    def setup(self) -> None:
        # Perform OTAA join, establish session
        
    def execute(self, device, gateway, capture) -> None:
        # Execute attack logic, capture packets
        
    def analyze(self, capture) -> AttackAnalysisResult:
        # Analyze captured packets, detect vulnerabilities
        
    def teardown(self) -> None:
        # Clean up resources
```

### Packet Capture & Analysis

```python
# Packet capture during attack execution
capture = PacketCapture()
capture.capture_uplink(packet)
capture.capture_downlink(packet)

# Post-attack analysis
analyzer = ReplayAnalyzer(capture)
result = analyzer.analyze()
print(result.vulnerability_detected)  # True if NS accepted replay
```

## Security Considerations

⚠️ **Important:** This tool is designed for authorized security testing only.

**DO NOT:**
- Run attacks against production networks without authorization
- Use for malicious purposes or unauthorized access
- Test against third-party networks without permission

**DO:**
- Use in isolated test environments
- Follow responsible disclosure for found vulnerabilities
- Document all findings with reproduction steps
- Report critical vulnerabilities to affected vendors

See [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) for vulnerability taxonomy and defensive recommendations.

## Performance Notes

- Join flooding tested up to 100 joins/10 devices
- Replay attacks support configurable burst rates
- MAC command injection handles multiple command types
- Memory-efficient packet capture (stores metadata only)

For performance testing details, see Phase 5 documentation (in progress).

## Contributing

This is an academic/research project for security testing. Contributions welcome for:
- Additional attack scenarios
- New attack types (downlink attacks, etc.)
- Performance optimizations
- Documentation improvements

Please follow the existing code structure and test coverage standards.

## License

[To be determined]

## References

- [LoRaWAN 1.0.3 Specification](https://lora-alliance.org/resource_hub/lorawan-specification-v1-0-3/)
- [Semtech UDP Protocol](https://github.com/Lora-net/packet_forwarder/blob/master/PROTOCOL.TXT)
- Clean-room implementation following public specifications only

## Acknowledgments

Developed as part of security research on LoRaWAN Network Server implementations. All code is original work based on public protocol specifications.
