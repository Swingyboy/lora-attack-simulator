# Architecture Refactoring Plan

## Overview

This refactoring addresses fundamental structural issues in the package organization identified in architectural review (June 3, 2026).

**Goal**: Transform from multiple top-level packages into a cohesive single-root-package architecture.

## Current Problems

### 1. No Root Package
Multiple top-level packages look like separate libraries:
```
src/
  attacks/
  cli/
  lorawan/
  monitoring/
  sim_logging/
  simulator/
  transport/
```

### 2. Unclear Responsibilities
- `simulator/` mixes CLI state with LoRaWAN lifecycle
- `sim_logging` is a naming workaround
- `monitoring/` is actually a tool, not core code
- `transport/` placement unclear (too generic for LoRaWAN-specific use)

### 3. Architectural Inconsistency
- `simulator/lifecycle/join_helper.py` belongs in `lorawan/`
- `session.py` belongs in CLI layer
- No clear separation between app layer and domain layer

## Target Structure

```
src/
  lorawan_sim/                    # Single root package
    __init__.py
    
    app/                          # Application/CLI layer
      __init__.py
      cli.py                      # CLI entry point
      shell.py                    # Interactive shell
      session.py                  # Session management
    
    lorawan/                      # LoRaWAN domain
      __init__.py
      
      device/
        __init__.py
        model.py
        factory.py
      
      gateway/
        __init__.py
        model.py
        factory.py
      
      protocol/
        __init__.py
        frames.py
        crypto_v103.py
        mac_commands.py
      
      semtech/
        __init__.py
        codec.py
      
      lifecycle/                  # LoRaWAN workflows
        __init__.py
        join.py                   # join_helper.py renamed
      
      scenario/
        __init__.py
        loader.py
        schema.py
        schema_v1.py
        base_types.py
      
      strategy/
        __init__.py
        periodic_uplink.py
      
      transport/                  # LoRaWAN-specific transport
        __init__.py
        base.py                   # transport.py renamed
        udp.py
        in_memory.py
    
    attacks/                      # Attack framework
      __init__.py
      base.py
      runner.py
      replay.py
      join_abuse.py
      mac_abuse.py
      analyzer.py
      packet_capture.py
      validation.py
    
    common/                       # Shared utilities
      __init__.py
      logging.py                  # sim_logging/json_logger.py

tools/                            # Development utilities (not installed)
  chirpstack_monitor.py           # monitoring/chirpstack_monitor.py moved

examples/                         # No change
  attacks/

tests/                            # No change (import paths updated)
```

## Import Path Changes

### Before
```python
from cli.shell import Shell
from simulator.session import Session
from simulator.lifecycle.join_helper import perform_otaa_join
from lorawan.device.model import SimulatedDevice
from sim_logging.json_logger import configure_logging
from transport.udp import UDPTransport
from attacks.replay import ReplayAttack
```

### After
```python
from lorawan_sim.app.shell import Shell
from lorawan_sim.app.session import Session
from lorawan_sim.lorawan.lifecycle.join import perform_otaa_join
from lorawan_sim.lorawan.device.model import SimulatedDevice
from lorawan_sim.common.logging import configure_logging
from lorawan_sim.lorawan.transport.udp import UDPTransport
from lorawan_sim.attacks.replay import ReplayAttack
```

## Implementation Phases

### Phase 1: Create Root Package Structure ✅ Low Risk
**Estimated Time**: 30 minutes

1. Create `src/lorawan_sim/` directory structure
2. Create all `__init__.py` files
3. Add root `__init__.py` with version info
4. No code changes yet - just skeleton

**Risk**: None - just creating directories

---

### Phase 2: Move and Rename Files ⚠️ Medium Risk
**Estimated Time**: 1 hour

#### 2A: Move CLI Layer
- `cli/main.py` → `lorawan_sim/app/cli.py`
- `cli/shell.py` → `lorawan_sim/app/shell.py`
- `simulator/session.py` → `lorawan_sim/app/session.py`

#### 2B: Move LoRaWAN Domain
- `lorawan/*` → `lorawan_sim/lorawan/*` (recursive)
- `simulator/lifecycle/join_helper.py` → `lorawan_sim/lorawan/lifecycle/join.py`
- `transport/*` → `lorawan_sim/lorawan/transport/*`

#### 2C: Move Attacks
- `attacks/*` → `lorawan_sim/attacks/*` (recursive)

#### 2D: Move Common
- `sim_logging/json_logger.py` → `lorawan_sim/common/logging.py`

#### 2E: Move Tools
- `monitoring/chirpstack_monitor.py` → `tools/chirpstack_monitor.py`

**Risk**: File moves break imports temporarily

---

### Phase 3: Update All Imports 🔴 High Risk
**Estimated Time**: 2-3 hours

Update imports in ~50 files:

1. **Internal imports** (within lorawan_sim package)
   - Change relative imports to absolute
   - Update cross-module references

2. **Test imports** (tests/ directory)
   - Update all `PYTHONPATH=src` assumptions
   - Change to `from lorawan_sim.` prefix

3. **Entry point** (pyproject.toml)
   - Update console_scripts entry point
   - Change from `cli.main:main` to `lorawan_sim.app.cli:main`

4. **Example scripts** (if any)
   - Update any import statements

**Risk**: Missing import updates cause runtime failures

**Mitigation**: 
- Automated search/replace for common patterns
- Incremental testing after each module
- Use grep to find all imports before starting

---

### Phase 4: Update Configuration ⚠️ Medium Risk
**Estimated Time**: 30 minutes

1. Update `pyproject.toml`:
   - Change package name reference
   - Update entry point: `lorawan-sim = lorawan_sim.app.cli:main`
   - Update package discovery: `packages = ["lorawan_sim"]`

2. Update `.gitignore`:
   - Add `.venv/`, `.idea/`, `__pycache__/`
   - Add `*.egg-info/`, `.pytest_cache/`
   - Ensure `logs/`, `results/` excluded

3. Update `README.md`:
   - Update import examples
   - Update architecture section

**Risk**: Package installation fails

---

### Phase 5: Testing and Validation 🔴 Critical
**Estimated Time**: 1 hour

1. **Clean reinstall**:
   ```bash
   rm -rf .venv src/*.egg-info
   python3.12 -m venv .venv
   . .venv/bin/activate
   pip install -e .
   ```

2. **Run test suite**:
   ```bash
   python -m unittest discover -s tests -v
   ```

3. **Test CLI**:
   ```bash
   lorawan-sim shell
   lorawan-sim run examples/attacks/join-replay-v1.json
   ```

4. **Verify imports**:
   ```bash
   python -c "from lorawan_sim.app.shell import Shell; print('OK')"
   python -c "from lorawan_sim.lorawan.device.model import SimulatedDevice; print('OK')"
   python -c "from lorawan_sim.attacks.replay import ReplayAttack; print('OK')"
   ```

**Risk**: Runtime failures, missing imports, test failures

---

### Phase 6: Cleanup Old Structure ✅ Low Risk
**Estimated Time**: 15 minutes

1. Remove old directories:
   - `src/cli/`
   - `src/simulator/`
   - `src/sim_logging/`
   - `src/transport/` (if not used elsewhere)
   - `src/monitoring/`

2. Remove empty `__pycache__` directories

3. Clean `.egg-info` directories

**Risk**: None (only after Phase 5 passes)

---

## Risks and Mitigation

### High-Risk Areas

1. **Import updates** (Phase 3)
   - **Risk**: Missing imports cause runtime failures
   - **Mitigation**: 
     - Create import mapping file before starting
     - Use automated search/replace with verification
     - Test each module incrementally
     - Keep tests running continuously

2. **Test suite** (Phase 5)
   - **Risk**: Tests assume old import paths
   - **Mitigation**:
     - Update test imports before running
     - Use `PYTHONPATH` correctly
     - Test early and often

3. **Entry point** (Phase 4)
   - **Risk**: CLI command breaks
   - **Mitigation**:
     - Test `pip install -e .` after every config change
     - Verify `lorawan-sim` command works

### Migration Strategy

**Option A: Big Bang (Not Recommended)**
- Do all phases in one session
- High risk of missing imports
- Difficult to debug

**Option B: Incremental with Dual Support (Recommended)**
- Phase 1-2: Create new structure
- Phase 3: Add new imports alongside old (temporary)
- Phase 4-5: Test and validate
- Phase 6: Remove old structure
- Allows rollback at any point

## Estimation Summary

| Phase | Time | Risk | Prerequisites |
|-------|------|------|---------------|
| 1. Create structure | 30 min | Low | None |
| 2. Move files | 1 hour | Medium | Phase 1 |
| 3. Update imports | 2-3 hours | High | Phase 2 |
| 4. Update config | 30 min | Medium | Phase 3 |
| 5. Testing | 1 hour | Critical | Phase 4 |
| 6. Cleanup | 15 min | Low | Phase 5 |
| **Total** | **5-6 hours** | | |

## Success Criteria

✅ All tests passing  
✅ CLI command works (`lorawan-sim shell`)  
✅ Attack scenarios run successfully  
✅ No old import paths remaining  
✅ Clean package structure (`lorawan_sim/` only)  
✅ Documentation updated  

## Rollback Plan

If Phase 3-5 fail:
1. Revert to previous commit
2. Keep Phase 1-2 changes as draft
3. Fix specific import issues
4. Retry incrementally

## Next Steps

1. **Review this plan** with user
2. **Get approval** to proceed
3. **Start Phase 1** (low risk)
4. **Incremental commits** after each phase
5. **Continuous testing** throughout

---

**Document Version**: 1.0  
**Created**: June 3, 2026  
**Status**: Awaiting approval
