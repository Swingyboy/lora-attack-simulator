"""
LoRaWAN Attack Simulator

A LoRaWAN Network Server offensive-security testing framework.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("lora-attack-toolkit")
except PackageNotFoundError:
    # Source checkout without installed metadata.
    __version__ = "1.0.0"

__author__ = "Swingyboy"

# Package metadata
__all__ = [
    "__version__",
    "__author__",
]
