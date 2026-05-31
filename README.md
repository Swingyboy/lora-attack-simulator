# lorawan-sim

LoRaWAN simulator MVP with modular architecture.

## Features (MVP)

- OTAA join workflow (LoRaWAN 1.0.3 strategy)
- Periodic unconfirmed uplink generation
- Semtech UDP gateway packet-forwarder emulation
- Structured JSON logs
- Scenario validation + execution via CLI

## Commands

```bash
lorawan-sim validate examples/debug-join-uplink.json
lorawan-sim run examples/debug-join-uplink.json
```

## Dev setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
PYTHONPATH=src python3 -m unittest discover -s src/lorawan_sim/tests -q
```
