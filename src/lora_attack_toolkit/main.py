#!/usr/bin/env python3
"""Application entry point for LoRAT (LoRa Attack Toolkit).

Responsibilities:
- Argument parsing
- Attack plugin bootstrap
- Session creation
- Logging initialisation
- Launching the interactive console

Command implementations live in app/console.py.
Attack execution is delegated to runner.py via Session.
"""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    """Bootstrap the application and start the interactive console."""
    from lora_attack_toolkit.attacks.bootstrap import register_builtin_attacks
    from lora_attack_toolkit.logging.logging import configure_logging
    from lora_attack_toolkit.runtime.session import Session
    from lora_attack_toolkit.app.console import LoRaWANConsole

    parser = argparse.ArgumentParser(
        prog="lorat",
        description=(
            "LoRAT (LoRa Attack Toolkit) — "
            "Offensive security testing framework for LoRaWAN Network Servers"
        ),
        epilog=(
            "Run without arguments for interactive mode. "
            "Pass a command string to execute a single command."
        ),
    )
    parser.add_argument("--version", action="version", version="LoRAT 0.2.0")
    parser.add_argument(
        "command",
        nargs="*",
        help="Console command to execute (e.g., 'show scenarios', 'use scenario run')",
    )
    args = parser.parse_args()

    # ── Bootstrap ────────────────────────────────────────────────────────────
    register_builtin_attacks()

    # ── Session ──────────────────────────────────────────────────────────────
    session = Session()

    # ── Logging ──────────────────────────────────────────────────────────────
    configure_logging(
        level="INFO",
        session_id=session.session_id,
        mask_secrets=True,
        use_colors=True,
    )

    # ── Console ──────────────────────────────────────────────────────────────
    console = LoRaWANConsole(session=session)

    if args.command:
        console.onecmd(" ".join(args.command))
        return 0

    try:
        console.cmdloop()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
