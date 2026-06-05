"""Tests for join replay generators."""

from __future__ import annotations

import unittest

from lora_attack_toolkit.attacks.builtin.join_replay_generators import (
    DuplicateDevNonceGenerator,
    IncrementingDevNonceGenerator,
    MemoryDepthDevNonceGenerator,
    RollbackDevNonceGenerator,
)


class TestDuplicateDevNonceGenerator(unittest.TestCase):
    """Test DuplicateDevNonceGenerator functionality."""
    
    def test_generate_duplicate_sequence(self) -> None:
        """Test generator produces [dev_nonce, dev_nonce]."""
        dev_nonce = b"\xAB\xCD"
        generator = DuplicateDevNonceGenerator(dev_nonce)
        
        sequence = generator.generate()
        
        self.assertEqual(len(sequence), 2)
        self.assertEqual(sequence[0], dev_nonce)
        self.assertEqual(sequence[1], dev_nonce)
        self.assertIs(sequence[0], sequence[1])  # Same object reference
    
    def test_different_devnonces(self) -> None:
        """Test generator works with different DevNonce values."""
        test_values = [
            b"\x00\x00",
            b"\xFF\xFF",
            b"\x12\x34",
            b"\xDE\xAD",
        ]
        
        for dev_nonce in test_values:
            with self.subTest(dev_nonce=dev_nonce.hex()):
                generator = DuplicateDevNonceGenerator(dev_nonce)
                sequence = generator.generate()
                
                self.assertEqual(len(sequence), 2)
                self.assertEqual(sequence[0], dev_nonce)
                self.assertEqual(sequence[1], dev_nonce)


class TestRollbackDevNonceGenerator(unittest.TestCase):
    """Test RollbackDevNonceGenerator functionality."""
    
    def test_generate_rollback_sequence(self) -> None:
        """Test generator produces [baseline, rollback]."""
        baseline = 100
        rollback = 99
        generator = RollbackDevNonceGenerator(baseline, rollback)
        
        sequence = generator.generate()
        
        self.assertEqual(len(sequence), 2)
        self.assertEqual(sequence[0], b"\x64\x00")  # 100 little-endian
        self.assertEqual(sequence[1], b"\x63\x00")  # 99 little-endian
    
    def test_rollback_with_different_values(self) -> None:
        """Test generator with various baseline/rollback pairs."""
        test_cases = [
            (10, 5),
            (1000, 500),
            (65535, 0),
            (256, 255),
        ]
        
        for baseline, rollback in test_cases:
            with self.subTest(baseline=baseline, rollback=rollback):
                generator = RollbackDevNonceGenerator(baseline, rollback)
                sequence = generator.generate()
                
                self.assertEqual(len(sequence), 2)
                
                # Verify values
                baseline_int = int.from_bytes(sequence[0], 'little')
                rollback_int = int.from_bytes(sequence[1], 'little')
                
                self.assertEqual(baseline_int, baseline)
                self.assertEqual(rollback_int, rollback)
                self.assertGreater(baseline_int, rollback_int)
    
    def test_boundary_values(self) -> None:
        """Test generator with boundary values."""
        # Min/max 16-bit values
        generator_max = RollbackDevNonceGenerator(65535, 65534)
        sequence_max = generator_max.generate()
        
        self.assertEqual(int.from_bytes(sequence_max[0], 'little'), 65535)
        self.assertEqual(int.from_bytes(sequence_max[1], 'little'), 65534)
        
        # Zero values
        generator_zero = RollbackDevNonceGenerator(1, 0)
        sequence_zero = generator_zero.generate()
        
        self.assertEqual(int.from_bytes(sequence_zero[0], 'little'), 1)
        self.assertEqual(int.from_bytes(sequence_zero[1], 'little'), 0)


class TestMemoryDepthDevNonceGenerator(unittest.TestCase):
    """Test MemoryDepthDevNonceGenerator functionality."""
    
    def test_generate_none_sequence(self) -> None:
        """Test generator produces N None values."""
        count = 10
        generator = MemoryDepthDevNonceGenerator(count)
        
        sequence = generator.generate()
        
        self.assertEqual(len(sequence), count)
        for item in sequence:
            self.assertIsNone(item)
    
    def test_different_counts(self) -> None:
        """Test generator with various count values."""
        test_counts = [1, 5, 10, 50, 100, 1000]
        
        for count in test_counts:
            with self.subTest(count=count):
                generator = MemoryDepthDevNonceGenerator(count)
                sequence = generator.generate()
                
                self.assertEqual(len(sequence), count)
                self.assertTrue(all(item is None for item in sequence))
    
    def test_zero_count(self) -> None:
        """Test generator with zero count produces empty list."""
        generator = MemoryDepthDevNonceGenerator(0)
        sequence = generator.generate()
        
        self.assertEqual(len(sequence), 0)
        self.assertEqual(sequence, [])


class TestIncrementingDevNonceGenerator(unittest.TestCase):
    """Test IncrementingDevNonceGenerator functionality."""
    
    def test_generate_incrementing_sequence(self) -> None:
        """Test generator produces [start, start+1, start+2, ...]."""
        start = 100
        count = 5
        generator = IncrementingDevNonceGenerator(start, count)
        
        sequence = generator.generate()
        
        self.assertEqual(len(sequence), count)
        
        for i, dev_nonce in enumerate(sequence):
            expected_value = start + i
            actual_value = int.from_bytes(dev_nonce, 'little')
            self.assertEqual(actual_value, expected_value)
    
    def test_incrementing_from_zero(self) -> None:
        """Test generator starting from zero."""
        generator = IncrementingDevNonceGenerator(0, 10)
        sequence = generator.generate()
        
        self.assertEqual(len(sequence), 10)
        
        for i, dev_nonce in enumerate(sequence):
            self.assertEqual(int.from_bytes(dev_nonce, 'little'), i)
    
    def test_incrementing_large_range(self) -> None:
        """Test generator with large count."""
        start = 1000
        count = 100
        generator = IncrementingDevNonceGenerator(start, count)
        
        sequence = generator.generate()
        
        self.assertEqual(len(sequence), count)
        self.assertEqual(int.from_bytes(sequence[0], 'little'), start)
        self.assertEqual(int.from_bytes(sequence[-1], 'little'), start + count - 1)
    
    def test_single_value(self) -> None:
        """Test generator with count=1."""
        start = 42
        generator = IncrementingDevNonceGenerator(start, 1)
        
        sequence = generator.generate()
        
        self.assertEqual(len(sequence), 1)
        self.assertEqual(int.from_bytes(sequence[0], 'little'), start)
    
    def test_zero_count(self) -> None:
        """Test generator with zero count produces empty list."""
        generator = IncrementingDevNonceGenerator(100, 0)
        sequence = generator.generate()
        
        self.assertEqual(len(sequence), 0)
        self.assertEqual(sequence, [])
    
    def test_boundary_values(self) -> None:
        """Test generator near 16-bit boundaries."""
        # Near max value (but not exceeding)
        generator = IncrementingDevNonceGenerator(65530, 5)
        sequence = generator.generate()
        
        self.assertEqual(len(sequence), 5)
        self.assertEqual(int.from_bytes(sequence[0], 'little'), 65530)
        self.assertEqual(int.from_bytes(sequence[-1], 'little'), 65534)


if __name__ == "__main__":
    unittest.main()
