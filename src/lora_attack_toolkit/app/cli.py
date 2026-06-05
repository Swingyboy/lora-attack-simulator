#!/usr/bin/env python3
"""CLI entry point for LoRAT (LoRa Attack Toolkit)."""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    """Main entry point - starts interactive shell or executes command."""
    from lora_attack_toolkit.app.shell import LoRaWANShell
    from lora_attack_toolkit.attacks.bootstrap import register_builtin_attacks
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        prog="lorat",
        description="LoRAT (LoRa Attack Toolkit) - Offensive security testing framework for LoRaWAN Network Servers",
        epilog="For interactive mode, run without arguments. For command mode, pass shell commands as arguments.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="LoRAT 0.2.0",
    )
    parser.add_argument(
        "command",
        nargs="*",
        help="Shell command to execute (e.g., 'show scenarios', 'use join-replay-v1 run')",
    )
    
    args = parser.parse_args()
    
    # Bootstrap: register all built-in attack plugins
    register_builtin_attacks()
    
    shell = LoRaWANShell()
    
    # If command provided, run single command mode
    if args.command:
        command = ' '.join(args.command)
        shell.onecmd(command)
        return 0
    
    # Otherwise start interactive mode
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
        return 130
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
