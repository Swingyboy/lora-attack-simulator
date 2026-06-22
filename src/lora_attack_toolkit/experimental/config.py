"""Experimental attack configuration (not part of the diploma scope).

The MAC-command abuse prototype lives under ``experimental`` and is excluded
from the registered, supported attacks. Its configuration dataclass and parser
are kept here rather than in the production ``config`` module so the production
schema only describes the three shipped attacks.

.. warning::

    These types are experimental and must not be used for security verdicts or
    diploma experiments. See :mod:`lora_attack_toolkit.experimental.mac_abuse`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MACCommandConfigV1:
    """MAC command abuse configuration (v1.0) — experimental."""

    command_type: str
    malformed: bool
    parameters: dict[str, Any] | None = None
    malformation_type: str | None = None


def parse_mac_command_config(config: dict[str, Any]) -> MACCommandConfigV1:
    """Parse MAC command abuse config from dict — experimental."""
    return MACCommandConfigV1(
        command_type=config["command_type"],
        malformed=config.get("malformed", False),
        parameters=config.get("parameters"),
        malformation_type=config.get("malformation_type"),
    )
