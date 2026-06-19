# AGENTS.md — LoRAT Contributor Guide for AI Agents

This file documents everything an AI coding agent needs to work effectively in
this repository: how to build and test the project, where things live, what the
architecture rules are, and what conventions to follow.

---

## Project Overview

**LoRAT** (LoRa Attack Toolkit) is a modular offensive-security testing
framework for LoRaWAN Network Servers. It simulates LoRaWAN end-devices and
gateways, executes protocol-level attack scenarios, and evaluates Network Server
responses.

- **Language:** Python 3.12+
- **Entry point:** `lorat` CLI (`src/lora_attack_toolkit/main.py`)
- **Package name:** `lorat` (installed via `pip install -e .`)
- **Python package:** `lora_attack_toolkit`

---

## Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

The `.venv` directory is in the repo root and is gitignored.

---

## Build & Test Commands

| Task | Command |
|------|---------|
| Run full test suite | `.venv/bin/python -m pytest -q` |
| Run a single test file | `.venv/bin/python -m pytest tests/attacks/test_uplink_forgery.py -v` |
| Run a specific test | `.venv/bin/python -m pytest tests/attacks/test_uplink_forgery.py::TestDetermineVerdict -v` |
| Lint (Ruff) | `.venv/bin/ruff check src/ tests/` |
| Type-check (mypy) | `.venv/bin/mypy src/` |
| Launch interactive CLI | `.venv/bin/lorat` |
| Execute one command | `.venv/bin/lorat "use uplink-forgery-v1"` |

Install dev tools with `pip install -e ".[dev]"`.

**Current baseline:** 242 tests, 0 failures (~160 s).

Always verify the full suite passes before committing. Run the targeted test
file first (fast feedback), then escalate to the full suite when confident.

---

## Repository Layout

```
src/lora_attack_toolkit/
├── main.py                  # CLI entry point (Typer + cmd2)
├── runner.py                # Scenario runner
├── config.py                # All dataclasses and schema parsers
│
├── attacks/                 # Attack plugin system
│   ├── base.py              # BaseAttack ABC
│   ├── registry.py          # AttackRegistry + AttackSpec
│   ├── bootstrap.py         # Registers all built-in attacks
│   ├── context.py           # AttackContext (dependency injection)
│   ├── result.py            # AttackResult
│   ├── validation.py        # Validation profiles (expected behavior)
│   ├── packet_capture.py    # PacketCapture helper
│   ├── analyzer.py          # Post-run analysis
│   └── builtin/             # Concrete attack implementations
│       ├── join_devnonce.py
│       ├── replay.py
│       ├── mac_abuse.py
│       └── uplink_forgery.py
│
├── runtime/                 # Device and gateway simulators
│   ├── device.py            # SimulatedDevice
│   ├── gateway.py           # GatewaySimulator
│   └── session.py           # DeviceRuntime (FCnt, session keys, ADR state)
│
├── lorawan/                 # LoRaWAN protocol primitives
│   ├── frames.py            # PHY frame building / parsing
│   ├── crypto.py            # MIC calculation, encryption
│   ├── join.py              # JoinRequest / JoinAccept
│   ├── mac_commands.py      # MAC command encoding
│   ├── radio.py             # Radio channel model
│   └── semtech_udp.py       # Semtech UDP framing helpers
│
├── transport/               # Transport abstraction
│   ├── transport.py         # Abstract Transport base
│   ├── udp.py               # UDP socket layer
│   ├── in_memory.py         # In-memory transport (tests)
│   └── resilient.py         # Retry / reconnect wrapper
│
├── app/                     # Interactive shell and CLI helpers
└── logging/                 # Structured logging setup

tests/
├── attacks/                 # Attack-level tests
├── protocol/                # LoRaWAN protocol unit tests
├── radio/                   # Radio / channel tests
├── transport/               # Transport layer tests
├── test_device_crypto_flow.py
└── test_scenario_loader.py

examples/attacks/            # Example JSON scenarios (used by `show scenarios`)
docs/reviews/                # Verification reports
```

---

## Architecture Rules

### Dependency Direction

```
Attack
  → Device  (SimulatedDevice)
      → Radio  (Radio)
      → Session  (DeviceRuntime)
  → Gateway  (GatewaySimulator)
      → Transport  (abstract)
```

Attacks must **not** reach past the device/gateway boundary into lorawan or
transport internals. All protocol behavior must be invoked through
`SimulatedDevice` or `GatewaySimulator` methods.

### Attack Layer Rules

- Every attack inherits `BaseAttack` and implements `run(ctx: AttackContext) -> AttackResult`.
- Attacks access services only through `ctx` — never instantiate `SimulatedDevice` directly.
- Attacks must **not** implement radio logic, channel selection, MIC calculation,
  or FCnt management. These live in `device`, `lorawan`, or `radio` modules.
- Attacks must **not** import from `transport` directly.
- Keep attack modules thin: describe *what to do*, not *how a device behaves*.

### Device Layer Rules

- `SimulatedDevice` is the single place where channel selection, duty-cycle
  tracking, and MAC state live.
- **`SimulatedDevice.select_uplink_radio(uplink_index, fallback)`** is the
  canonical channel-selection entry point. All attacks call this; none implement
  their own channel selection.
- `device.runtime` (`DeviceRuntime`) holds mutable session state: FCntUp,
  FCntDown, DevAddr, session keys, ADR state, CFList channels.

### Configuration Rules

- All config dataclasses live in `config.py`.
- Every attack type has a `*ConfigV1` dataclass and a `parse_*_config(dict)`
  function.
- Config parsers validate inputs and raise `ValueError` for unknown enum values.
- Default field values must match the example JSON scenarios in `examples/attacks/`.

### No `attacks/common/` directory

The directory `src/lora_attack_toolkit/attacks/common/` does **not exist** and
must not be created. Logic that seems "common to multiple attacks" actually
belongs in `device/`, `lorawan/`, or `radio/`.

---

## Adding a New Attack

1. **Create** `src/lora_attack_toolkit/attacks/builtin/<attack_name>.py`
   - Define a `*ConfigV1` dataclass and `parse_*_config()` function in `config.py`.
   - Implement a class inheriting `BaseAttack` with `name = "<attack_name>"`.
   - Implement `run(self, ctx: AttackContext) -> AttackResult`.

2. **Register** in `src/lora_attack_toolkit/attacks/bootstrap.py`:
   ```python
   _register_builtin(
       AttackSpec(
           name="<attack_name>",
           attack_class=MyAttack,
           config_parser=parse_my_config,
           title="Human-Readable Title",
           category="<category>",
           attack_id="<attack-name>-v1",
           description="One-line description",
       )
   )
   ```

3. **Add an example scenario** `examples/attacks/<attack-name>-v1.json`.
   - The scenario is auto-discovered by `show scenarios` via `ScenarioMetadata.from_file()`.

4. **Add tests** in `tests/attacks/test_<attack_name>.py`.
   - Cover: config parsing, registry registration, scenario file loading,
     packet construction (if any), verdict logic, end-to-end `attack.run(ctx)`.

5. **Add a validation profile** in `attacks/validation.py` if the attack
   evaluates specific security criteria.

---

## Existing Attack Types

| Name | File | Category | Description |
|------|------|----------|-------------|
| `join_devnonce` | `builtin/join_devnonce.py` | `join_devnonce` | DevNonce replay and monotonicity validation |
| `uplink_replay` | `builtin/replay.py` | `replay` | Capture and retransmit a valid uplink frame |
| `mac_command_injection` | `builtin/mac_abuse.py` | `mac_abuse` | Inject legitimate or malformed MAC commands |
| `uplink_forgery` | `builtin/uplink_forgery.py` | `forgery` | Forged uplinks with manipulated MIC, FCnt, DevAddr |

Aliases: `mac_command_injection` is also registered as `mac_malformed`.

---

## Configuration Schema Overview

Top-level JSON scenario keys:

```json
{
  "scenario":  { "description": "...", "timeout_sec": 60 },
  "target":    { "name": "...", "transport": "semtech_udp", "host": "...", "port": 1700 },
  "gateway":   { "gateway_eui": "...", "radio": { "region": "EU868", ... } },
  "device":    { "lorawan_version": "1.0.3", "activation": { "mode": "OTAA", ... } },
  "attack":    { "type": "<attack_name>", "config": { ... } },
  "expected":  { "profile": "<validation_profile_name>" },
  "logging":   { "level": "info", "log_phy_payload": true }
}
```

Parsed by `config.py` — see `ScenarioConfig`, `AttackConfig`, `DeviceConfig`,
`GatewayConfig`, etc.

---

## Testing Conventions

- Use `pytest` with no plugins beyond the standard library.
- Use `unittest.mock.MagicMock` / `patch` for transport and gateway.
- Use `InMemoryTransport` for integration-style tests that need a real transport.
- Tests must not open real network sockets or require a live Network Server.
- Test class naming: `Test<Feature>` (e.g., `TestDetermineVerdict`).
- Test method naming: `test_<what_is_being_tested>` (e.g., `test_invalid_mic_no_dl_rejected`).

---

## Forgery Mode Reference (`uplink_forgery`)

| Mode | FCnt | DevAddr | MIC | Purpose |
|------|------|---------|-----|---------|
| `invalid_mic` | current | valid | corrupted | Verify NS rejects bad MIC |
| `valid_mic_modified_payload` | current | valid | recalculated | Verify simulator can produce valid forged frames |
| `fcnt_jump_forward` | current + delta | valid | corrupted | Probe large FCnt tolerance |
| `fcnt_reuse_with_modified_payload` | previous | valid | corrupted | Verify replay protection |
| `wrong_devaddr` | current | forged | corrupted | Verify session binding |
| `mac_command_forgery` | current | valid | corrupted | Probe MAC command auth |

Supported MAC commands for `mac_command_forgery`:
`DeviceTimeReq`, `LinkCheckReq`, `LinkADRAns`, `DutyCycleAns`, `RXParamSetupAns`

---

## Known Limitations

| Area | Status |
|------|--------|
| Transports | Semtech UDP only; MQTT and WebSocket not implemented |
| ChannelMask enforcement | `LinkADRReq` updates `DeviceRuntime.adr.ch_mask` but `Radio` channels are not filtered |
| ADR data-rate propagation | ADR DR updates `DeviceRuntime.adr.data_rate` but not `Radio._data_rate` |
| Duty-cycle airtime | `Radio.record_transmission()` exists but is not called post-transmit |
| ABP activation | Not tested; `perform_join=false` requires pre-provisioned session keys |

---

## Commit Message Convention

Include the Co-authored-by trailer when commits are generated by Copilot:

```
Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```
