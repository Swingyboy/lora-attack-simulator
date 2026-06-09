"""Backward-compat re-export. Use lora_attack_toolkit.main instead."""
from lora_attack_toolkit.main import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
