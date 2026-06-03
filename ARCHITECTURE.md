# Architecture Overview

This document describes the architecture of the LoRaWAN Attack Simulator after Phase 1-4 refactoring (June 2025).

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Shell                             │
│  (Interactive REPL: use, show, set, run, validate)          │
└───────────────┬─────────────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────┐
│                      Session Model                           │
│  - Loaded scenario data                                      │
│  - Runtime parameter overrides                               │
│  - Deep merge for effective scenario                         │
└───────────────┬─────────────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────┐
│                     Attack Runner                            │
│  - Orchestrates attack lifecycle                             │
│  - Setup → Execute → Teardown → Analyze                      │
└───────────────┬─────────────────────────────────────────────┘
                │
                ├──────────────────┬──────────────────┬────────┐
                ▼                  ▼                  ▼        ▼
         ┌──────────┐       ┌──────────┐      ┌──────────┐  ...
         │  Replay  │       │   Join   │      │   MAC    │
         │  Attack  │       │  Abuse   │      │  Abuse   │
         └──────────┘       └──────────┘      └──────────┘
                │                  │                  │
                └──────────────────┴──────────────────┘
                                   │
                ┌──────────────────┴──────────────────┐
                ▼                                      ▼
         ┌─────────────┐                      ┌─────────────┐
         │   Device    │                      │   Gateway   │
         │  Simulator  │                      │  Simulator  │
         └─────────────┘                      └─────────────┘
                │                                      │
                └──────────────────┬───────────────────┘
                                   ▼
                          ┌────────────────┐
                          │   Transport    │
                          │  (UDP/Memory)  │
                          └────────────────┘
```

## Module Structure

### `src/cli/`
**Command-Line Interface**

- `shell.py`: Interactive REPL using `cmd.Cmd`
  - Commands: use, show, set, reset, run, validate
  - Session management integration
  - Logging configuration

**Key Design**: Uses stdlib `cmd.Cmd` (no external dependencies like typer/rich)

### `src/simulator/`
**Session Management**

- `session.py`: Session model
  - Tracks loaded scenario and overrides
  - Deep merge for effective scenario
  - Dot-notation parameter paths
  - Immutable merge (preserves base scenario)

**Refactored in Phase 2**: Added deep merge, parameter API

### `src/attacks/`
**Attack Framework**

- `runner.py`: Attack orchestration
  - Attack lifecycle management
  - Result aggregation and file output
  - Session-based result paths (`results/<session-id>/`)

- `base.py`: `BaseAttack` abstract class
  - Standard lifecycle: setup() → execute() → teardown() → analyze()
  - Packet capture integration
  - Expected behavior validation

- `replay.py`, `join_abuse.py`, `mac_abuse.py`: Attack implementations

**Refactored in Phase 3**: Removed v0.9 legacy support

### `src/lorawan/`
**LoRaWAN Domain Logic**

#### `scenario/`
- `loader.py`: JSON scenario loading
  - v1.0 format only (v0.9 removed)
  - Schema validation
  - Attack config parsing

- `schema_v1.py`: v1.0 dataclasses
  - `AttackScenarioV1`: Root schema
  - Typed attack configs (replay, join abuse, MAC)

#### `device/`, `gateway/`
- Device and gateway simulators
- Factories for dependency injection
- LoRaWAN 1.0.3 protocol implementation

#### `protocol/`
- `lorawan/`: Frame building, crypto (AES-128)
- `semtech/`: UDP packet codec

**Clean-room implementation**: No code reuse from other LoRaWAN projects

### `src/sim_logging/`
**Logging Subsystem**

- `json_logger.py`: Dual-output logging
  - Console: Colored, human-readable
  - File: JSONL structured logs
  - **Precedence Model**: cli_override > scenario > framework_default
  - Secret masking for hex keys
  - TRACE log level support

**Refactored in Phase 2**: Added explicit precedence enforcement

### `src/adapters/transport/`
**Transport Adapters**

- `udp.py`: Semtech UDP transport
- `memory.py`: In-memory transport (testing)

**Pluggable design**: All inherit from `TransportClient` ABC

## Key Design Decisions

### 1. Session-Based Parameter Management

**Problem**: Direct scenario modification made rollback difficult.

**Solution**: Session model with runtime overrides:
- Base scenario remains immutable
- Overrides tracked separately
- `get_effective_scenario()` merges on-demand
- `set` command stores overrides
- `reset` command clears overrides

**Benefits**:
- Rollback without reloading
- Clear separation of base vs. overridden state
- Auditability (can see what was changed)

### 2. Logging Precedence

**Problem**: CLI and scenario both set log level - which wins?

**Solution**: Explicit precedence model:
1. CLI overrides (highest)
2. Scenario config (medium)
3. Framework defaults (lowest)

**Implementation**: `LoggingConfig.set_level()` checks source precedence

**Benefits**:
- Predictable behavior
- CLI always wins (user expectation)
- Scenario can set defaults
- Framework never overrides user

### 3. Attack Runner Consolidation

**Problem**: Duplicate orchestration logic.

**Analysis**: "Duplication" was actually dead code!
- `ScenarioRunner`: Benign simulation (unused)
- `AttackRunner`: Attack execution (active)

**Solution**: Remove unused `ScenarioRunner`.

**Benefits**:
- Focused codebase (attacks only)
- No false "consolidation" complexity
- Attack lifecycle is the primary pattern

### 4. v0.9 Legacy Removal

**Problem**: Supporting two schema formats (v0.9 and v1.0).

**Analysis**: All examples migrated to v1.0.

**Solution**: Remove v0.9 loader and runner code (~150 lines).

**Benefits**:
- Single format to maintain
- Clearer migration path
- Reduced cognitive load

### 5. Result File Organization

**Problem**: Results saved next to scenario files (clutters examples/).

**Solution**: Session-based organization:
- OLD: `examples/attacks/scenario.results.json`
- NEW: `results/<session-id>/scenario.results.json`

**Benefits**:
- Clean examples directory
- Session-based tracking
- `.gitignore` excludes `results/`

## Data Flow: Attack Execution

```
1. CLI: user types "use join-replay-v1"
   ├─> Shell calls session.load_scenario()
   └─> Session stores scenario_data

2. CLI: user types "set target.port 1701"
   ├─> Shell calls session.set_parameter()
   └─> Session stores in runtime_overrides

3. CLI: user types "run"
   ├─> Shell calls session.get_effective_scenario()
   ├─> Session merges scenario_data + runtime_overrides
   ├─> Shell creates AttackRunner
   ├─> Runner loads scenario, creates attack instance
   ├─> Attack lifecycle:
   │   ├─ setup():    Join network, capture baseline
   │   ├─ execute():  Inject malicious traffic
   │   ├─ teardown(): Stop gateway, cleanup
   │   └─ analyze():  Evaluate results, check criteria
   ├─> Runner saves results to results/<session-id>/
   └─> Shell displays summary
```

## Configuration Flow: Logging

```
1. Shell startup:
   ├─> configure_logging(level="INFO")
   └─> LoggingConfig.set_level("INFO", source="framework_default")
       └─> Precedence: 0 (lowest)

2. User types "set logging.level DEBUG":
   ├─> Shell calls reconfigure_level("DEBUG")
   └─> LoggingConfig.set_level("DEBUG", source="cli_override")
       └─> Precedence: 2 (highest)
       └─> Level changed to DEBUG

3. (Future) User runs scenario with logging.level=TRACE:
   ├─> configure_logging(level="TRACE", source="scenario")
   └─> LoggingConfig.set_level("TRACE", source="scenario")
       └─> Precedence: 1 (medium)
       └─> BLOCKED by cli_override (precedence 2 > 1)
       └─> DEBUG level retained
```

## Testing Strategy

### Current Test Coverage

- **6 passing tests** (Phase 1 refactoring)
- Test locations: `tests/` (top-level, not nested in `src/`)
- Test runner: stdlib `unittest` (no pytest)

### Test Structure

```
tests/
├── test_device_crypto_flow.py    # Device join/uplink crypto
├── test_scenario_loader.py       # Scenario JSON parsing
├── test_replay_attack.py         # Replay attack logic
├── test_join_abuse.py            # Join abuse attack logic
├── test_mac_abuse.py             # MAC command abuse logic
└── test_analyzer.py              # Attack result analysis
```

### Testing Philosophy

- **Integration-style tests**: No heavy mocking
- **Crypto validation**: Full AES-128 session key derivation
- **Protocol adherence**: LoRaWAN 1.0.3 MIC calculation

## Dependencies

### Production Dependencies

```
cryptography==3.3.2  # AES-128 crypto (LoRaWAN session keys)
```

**That's it!** No framework dependencies.

### Why So Few?

- **CLI**: stdlib `cmd.Cmd` + `argparse` (removed typer, rich, cmd2)
- **Logging**: stdlib `logging` + custom formatters
- **Testing**: stdlib `unittest` (no pytest)
- **Crypto**: Only external dependency (LoRaWAN requires AES-128)

**Refactored in Phase 1**: Removed unused dependencies

## Deployment

### Running Locally

```bash
# Setup
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e .

# Run tests
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -q

# Run shell
lorawan-sim shell
```

### Result Storage

- Session logs: `logs/session-<timestamp>.log` (JSONL)
- Attack results: `results/<session-id>/<scenario>.results.json`
- Both excluded from git via `.gitignore`

## Future Architecture Considerations

### Benign Simulation (Not Currently Implemented)

If benign (non-attack) simulation is needed:

1. **Don't resurrect ScenarioRunner** - it's legacy
2. **Use AttackRunner as reference** for orchestration pattern
3. **Create BenignRunner** with similar lifecycle
4. **Reuse device/gateway factories** (already shared)

### Multi-Session Support

Current design is single-session (one CLI per process).

For multi-session:
- Session IDs already exist (UUID-based)
- Would need session storage (filesystem or DB)
- Would need session switching commands
- Logging already session-aware

### Scenario v2.0 Format

If schema evolves:
- Keep `load_attack_scenario()` as loader entry point
- Add version detection: `if schema_version == "2.0"`
- New loader: `_load_v2_format()`
- Consider migration tool (v1.0 → v2.0)

**Don't support multiple versions long-term** - learned from v0.9 removal.

## Refactoring History

### Phase 1: Critical Blockers (✅ Complete)
- Fixed test suite imports (removed empty `__init__.py`)
- Verified git artifacts clean
- Verified shell logging bug fixed
- Removed unused dependencies (typer, rich, cmd2)

### Phase 2: Architectural Stabilization (✅ Complete)
- Session model already existed
- Implemented deep merge for runtime overrides
- Added logging precedence enforcement
- Removed unused `ScenarioRunner` (dead code)
- Fixed result file organization (session-based paths)

### Phase 3: Technical Debt Cleanup (✅ Complete)
- Removed v0.9 legacy support (~150 lines)
- Migrated to session API (`is_scenario_loaded()`)
- Audited logging initialization (no handler duplication)

### Phase 4: Documentation (✅ Complete)
- Documented session model API and deep merge
- Documented logging precedence rules
- This architecture document

**Total Changes**: ~350 lines removed, ~200 lines added (net -150 lines)

**Time**: 4 hours actual vs. 22-32 hours estimated

**Reason**: Many "issues" were already fixed or were dead code, not duplication.

---

**Document Version**: 1.0 (Post-Refactoring)  
**Last Updated**: June 3, 2025  
**Status**: Current architecture (Phases 1-4 complete)
