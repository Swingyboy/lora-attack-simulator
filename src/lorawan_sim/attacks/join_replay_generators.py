"""DevNonce sequence generators for join replay attacks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator


class DevNonceGenerator(ABC):
    """Base class for DevNonce sequence generators."""
    
    @abstractmethod
    def generate(self) -> list[bytes | None]:
        """
        Generate sequence of DevNonce values.
        
        Returns:
            List of DevNonce values to use in join sequence.
            None means device should auto-generate fresh DevNonce.
        """
        pass


class DuplicateDevNonceGenerator(DevNonceGenerator):
    """
    Generator for duplicate DevNonce attack (100 → 100).
    
    Tests if NS rejects duplicate DevNonce from same device.
    """
    
    def __init__(self, dev_nonce: bytes):
        """
        Initialize generator.
        
        Args:
            dev_nonce: The DevNonce to duplicate
        """
        self.dev_nonce = dev_nonce
    
    def generate(self) -> list[bytes | None]:
        """Generate: [dev_nonce, dev_nonce]"""
        return [self.dev_nonce, self.dev_nonce]


class RollbackDevNonceGenerator(DevNonceGenerator):
    """
    Generator for DevNonce rollback attack (100 → 99).
    
    Tests if NS accepts older DevNonce value (rollback protection).
    Applicable to LoRaWAN 1.0.3+.
    """
    
    def __init__(self, baseline: int, rollback: int):
        """
        Initialize generator.
        
        Args:
            baseline: First DevNonce value (higher)
            rollback: Second DevNonce value (lower)
        """
        self.baseline = baseline
        self.rollback = rollback
    
    def generate(self) -> list[bytes | None]:
        """Generate: [baseline, rollback]"""
        return [
            self.baseline.to_bytes(2, 'little'),
            self.rollback.to_bytes(2, 'little'),
        ]


class MemoryDepthDevNonceGenerator(DevNonceGenerator):
    """
    Generator for memory depth testing (1 → 2 → 3 → ... → N).
    
    Generates N joins with device auto-generating fresh DevNonces.
    Used to build up NS DevNonce history before verification phase.
    """
    
    def __init__(self, count: int):
        """
        Initialize generator.
        
        Args:
            count: Number of fresh DevNonces to generate
        """
        self.count = count
    
    def generate(self) -> list[bytes | None]:
        """
        Generate N None values (device will auto-generate DevNonces).
        
        Returns:
            List of None values, one per join attempt
        """
        return [None] * self.count


class IncrementingDevNonceGenerator(DevNonceGenerator):
    """
    Generator for incrementing DevNonce sequence (100 → 101 → 102 → ...).
    
    Alternative to memory depth - generates explicit DevNonce sequence
    instead of relying on device auto-generation.
    """
    
    def __init__(self, start: int, count: int):
        """
        Initialize generator.
        
        Args:
            start: Starting DevNonce value
            count: Number of DevNonces to generate
        """
        self.start = start
        self.count = count
    
    def generate(self) -> list[bytes | None]:
        """Generate: [start, start+1, start+2, ..., start+count-1]"""
        return [
            (self.start + i).to_bytes(2, 'little')
            for i in range(self.count)
        ]
