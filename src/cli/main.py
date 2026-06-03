#!/usr/bin/env python3
"""CLI entry point for LoRaWAN Offensive Security Testing Framework."""

from __future__ import annotations

import sys


def main() -> int:
    """Main entry point - starts interactive shell."""
    from cli.shell import LoRaWANShell
    
    shell = LoRaWANShell()
    
    # If args provided, run single command mode
    if len(sys.argv) > 1:
        # Pass command directly to shell
        command = ' '.join(sys.argv[1:])
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
