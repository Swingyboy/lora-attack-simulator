# Internal Logic and Runtime Architecture Review

# Purpose

This document contains additional architectural and implementation review feedback for the current version of the LoRaWAN Offensive Security Testing Framework.

The focus of this review is:

* runtime logic;
* execution flow;
* scenario/session behavior;
* logging behavior;
* attack orchestration;
* legacy compatibility;
* consistency of internal APIs.

The project already demonstrates strong progress and working functionality, but several architectural inconsistencies and partially completed refactors remain inside the implementation.

Addressing these issues now will significantly reduce future maintenance complexity.

---

# General Observation

The framework is currently transitioning from:

```text
prototype scripts
```

toward:

```text
modular offensive-security framework
```

However, several internal components still contain:

* legacy execution paths;
* duplicate responsibilities;
* partially migrated APIs;
* inconsistent runtime ownership;
* unfinished refactors.

The framework should now prioritize stabilization and normalization of internal behavior before adding new features or attack modules.

---

# Test Suite Status

The current test suite appears partially broken after the latest structural refactoring.

Observed issues include:

* imports referencing outdated package paths;
* renamed functions not reflected in tests;
* removed models still referenced;
* runtime components using deprecated interfaces.

Examples:

```text id="x3sgm8"
lorawan_sim.domain.*
```

while the corresponding package no longer exists.

Additional issues:

* tests expect `load_scenario()`;
* implementation now exposes `load_attack_scenario()`;
* removed models such as `ScenarioConfig` are still referenced.

---

# Recommendation

Before further feature work:

* stabilize package structure;
* update all tests;
* remove dead imports;
* remove obsolete compatibility layers.

The test suite should become authoritative again.

---

# Duplicate Runner Logic

The project currently appears to contain two partially overlapping execution systems.

Examples:

```text id="epuk34"
simulator/scenario_runner.py
attacks/runner.py
```

This creates ambiguity regarding:

* execution ownership;
* orchestration responsibility;
* runtime lifecycle management.

---

# Problem

`scenario_runner.py` appears to implement:

* baseline join/uplink workflow;
* runtime orchestration.

Meanwhile:

```text id="e9g8i2"
attacks/runner.py
```

implements:

* attack execution orchestration.

This creates duplicate runtime responsibility.

---

# Recommendation

The framework should contain only one authoritative runtime execution engine.

Recommended direction:

```text id="yr8kmh"
runtime/runner.py
```

Responsibilities:

* scenario lifecycle;
* transport lifecycle;
* device/gateway lifecycle;
* attack orchestration;
* validation flow;
* result evaluation.

Attack modules themselves should only contain attack behavior.

---

# Legacy v0.9 Compatibility Layer

The implementation still contains compatibility logic for legacy v0.9 scenarios.

Examples include:

* legacy scenario loaders;
* deprecated config models;
* version branching logic.

This significantly increases complexity while the project already intends to remove deprecated scenarios.

---

# Recommendation

Completely remove:

* v0.9 scenario loading;
* deprecated scenario parsers;
* compatibility branches;
* obsolete config classes.

The framework should support only:

```text id="j1m3sp"
schema_version = "1.0"
```

This will simplify:

* validation;
* runtime behavior;
* maintenance;
* scenario evolution.

---

# Session Override Logic Problem

The session model currently appears incomplete.

Example behavior:

```python id="8mhfqx"
# TODO: Deep merge runtime_overrides into scenario_data
return self.scenario_data
```

This creates architectural inconsistency because:

* CLI allows runtime parameter modification;
* session stores overrides;
* effective runtime configuration is not actually merged correctly.

---

# Recommendation

Choose one consistent approach.

Either:

## Option A — Mutable Scenario Model

`set` commands directly modify:

```text id="rn5xxy"
session.scenario_data
```

and remove:

```text id="sgqjlc"
runtime_overrides
```

---

## Option B — Immutable Base Scenario

Keep:

```text id="4w1xol"
runtime_overrides
```

and implement proper deep merge logic inside:

```text id="jlwmvb"
get_effective_scenario()
```

This option is cleaner architecturally.

---

# Session API Inconsistency

The shell implementation currently appears to bypass official session APIs.

Observed behavior:

```python id="z5q3m1"
self.session.scenario_data = ...
self.session.scenario_name = ...
self.session.scenario_path = ...
```

instead of using:

```python id="r57mbx"
self.session.load_scenario(...)
```

---

# Recommendation

The shell should never manipulate session internals directly.

All session state modifications should go through explicit session APIs.

Benefits:

* better encapsulation;
* validation centralization;
* future persistence support;
* easier debugging.

---

# Logging Level Precedence Problem

The current logging system appears to contain multiple competing configuration sources.

Potential sources:

* shell startup defaults;
* scenario logging section;
* runtime CLI overrides.

This may create unpredictable behavior.

---

# Recommendation

Define strict precedence rules.

Recommended order:

```text id="c2p6l3"
CLI/session overrides
    >
scenario configuration
    >
framework defaults
```

This should be explicitly implemented and documented.

---

# Session Logging Continuity Problem

Current behavior suggests that log configuration may be recreated during runtime execution.

This risks:

* replacing handlers;
* creating new log files;
* breaking session-oriented logging.

---

# Recommendation

The logging system should initialize once per CLI session.

Runtime execution should only:

* update log level;
* update contextual metadata;
* append execution context.

The framework should never recreate the logging subsystem during `run`.

---

# Shell Logging Bug

The shell currently appears to reference:

```python id="v2dw4t"
_set_logging_param(...)
```

while the implementation itself does not exist.

This likely breaks commands such as:

```text id="qf64gf"
set logging.level debug
```

---

# Recommendation

Fix immediately.

Logging configuration is now a core CLI feature and must behave consistently.

---

# Result Artifact Placement Problem

Current behavior stores execution artifacts near scenario templates.

Example:

```text id="jlwm4p"
examples/attacks/join-replay-v1.results.json
```

This creates pollution inside the scenario directory.

---

# Recommendation

Scenario templates should remain read-only.

Execution artifacts should be stored separately.

Recommended structure:

```text id="76klc9"
results/<session-id>/<scenario-id>.result.json
```

---

# MAC Attack Logic Problem

The current MAC attack scenario still models:

```json id="l1b1ec"
"command_type": "LinkADRReq"
```

However:

```text id="1c9e98"
LinkADRReq
```

is a downlink Network Server → Device MAC command.

This does not align with the current MVP architecture focused on:

```text id="z1s76z"
uplink NS-facing attack simulation
```

---

# Recommendation

Replace the scenario with uplink-oriented malformed MAC behavior.

Examples:

```json id="bfpjlwm"
"command_type": "LinkADRAns"
```

or:

* malformed FOpts;
* invalid FOpts length;
* malformed MAC answers;
* invalid FPort=0 payloads.

---

# Dependency Inconsistency

The project currently includes dependencies such as:

* `cmd2`
* `typer`

while implementation still uses:

* standard `cmd`;
* `argparse`.

This creates inconsistency between:

* architecture direction;
* actual implementation;
* dependency usage.

---

# Recommendation

Choose one direction consistently.

Either:

* fully adopt these libraries;
* or temporarily remove them until migration is complete.

---

# Session Model Recommendation

The project should introduce a dedicated session model.

Recommended structure:

```text id="8r8nj5"
runtime/session.py
```

Suggested fields:

```python id="g3fjlwm"
session_id
active_scenario
scenario_path
runtime_overrides
log_file
started_at
```

Benefits:

* cleaner runtime ownership;
* future persistence;
* easier debugging;
* future scripting support;
* cleaner shell integration.

---

# Secret Exposure Problem

Current shell output partially exposes secrets.

Even if logging masks keys, shell output should also mask:

* AppKey;
* NwkKey;
* session keys;
* root keys.

Secrets should never be displayed in plain text by default.

---

# Runtime Artifact Pollution

The repository/archive still contains runtime-generated artifacts such as:

```text id="jlwm5s"
logs/
results/
```

These should not be committed or included in archives.

---

# Repository Cleanup Recommendations

The following should be excluded:

```text id="jlwm06"
.venv/
__pycache__/
*.pyc
.idea/
.git/
*.egg-info/
logs/
results/
```

---

# Final Recommendation

At the current stage of the project, architectural stabilization is more important than introducing additional attack features.

The framework should prioritize:

* runtime normalization;
* session consistency;
* legacy removal;
* cleanup;
* centralized orchestration;
* test stabilization;
* clear runtime ownership;
* elimination of duplicate execution paths.

Without these changes, the framework will become significantly harder to evolve as additional attacks and transports are introduced.
