"""Tests for LoRAT versioning: single source of truth in pyproject.toml."""

from __future__ import annotations

import subprocess

import pytest

EXPECTED_VERSION = "1.0.0"
DIST_NAME = "lora-attack-toolkit"


@pytest.mark.unit
def test_version_value() -> None:
    """__version__ resolves to the expected version string."""
    from lora_attack_toolkit import __version__

    assert __version__ == EXPECTED_VERSION


@pytest.mark.unit
def test_version_matches_metadata() -> None:
    """__version__ matches the installed distribution metadata."""
    from importlib.metadata import version

    from lora_attack_toolkit import __version__

    assert __version__ == version(DIST_NAME)


@pytest.mark.unit
def test_old_distribution_name_absent() -> None:
    """The old 'lorat' distribution name must not resolve after the rename."""
    from importlib.metadata import PackageNotFoundError, version

    with pytest.raises(PackageNotFoundError):
        version("lorat")


@pytest.mark.unit
def test_cli_version_output() -> None:
    """lorat --version exits 0 and outputs 'LoRAT 1.0.0'."""
    result = subprocess.run(
        ["lorat", "--version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert EXPECTED_VERSION in result.stdout or EXPECTED_VERSION in result.stderr


@pytest.mark.unit
def test_provenance_toolkit_version() -> None:
    """Provenance toolkit_version() returns the current version (not 'unknown')."""
    from lora_attack_toolkit.provenance import toolkit_version

    assert toolkit_version() == EXPECTED_VERSION
