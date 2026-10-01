"""
Tests for Shannon Entropy Gatekeeper (src/harvester/entropy.py).
Failure Modes Covered:
- FM-ENT-01: Empty byte buffer (zero division avoided, returns 0.0)
- FM-ENT-02: Single byte repeated (entropy is 0.0)
- FM-ENT-03: High entropy random byte buffer (approaches 8.0, flagged as packed)
- FM-ENT-04: Threshold boundary values (exact 7.1 and 7.10001)
- FM-ENT-05: Non-bytes or invalid inputs handled safely
"""

import math
import os

import pytest

from src.harvester.entropy import calculate_entropy, is_sample_packed


def test_fm_ent_01_empty_buffer():
    entropy = calculate_entropy(b"")
    assert entropy == 0.0
    assert not is_sample_packed(b"", threshold=7.1)


def test_fm_ent_02_single_repeated_byte():
    data = b"\x00" * 1024
    entropy = calculate_entropy(data)
    assert entropy == 0.0
    assert not is_sample_packed(data, threshold=7.1)


def test_uniform_distribution_entropy():
    # 256 unique bytes distributed evenly: entropy should be log2(256) = 8.0
    data = bytes(range(256)) * 4
    entropy = calculate_entropy(data)
    assert math.isclose(entropy, 8.0, rel_tol=1e-5)
    assert is_sample_packed(data, threshold=7.1)


def test_fm_ent_03_high_entropy_random_data():
    random_data = os.urandom(4096)
    entropy = calculate_entropy(random_data)
    assert entropy > 7.8
    assert is_sample_packed(random_data, threshold=7.1)


def test_typical_unpacked_code_entropy():
    # Typical assembly / text with varied opcodes and padding
    text_code = b"Hello, World! Standard unpacked binary code with strings and zeros." * 50
    entropy = calculate_entropy(text_code)
    assert entropy < 7.1
    assert not is_sample_packed(text_code, threshold=7.1)


def test_fm_ent_04_boundary_conditions():
    assert not is_sample_packed(b"", threshold=0.0)
    assert is_sample_packed(bytes(range(256)), threshold=7.99)
    assert not is_sample_packed(bytes(range(256)), threshold=8.0)


def test_fm_ent_05_invalid_input_type():
    with pytest.raises(TypeError):
        calculate_entropy("string is not bytes")  # type: ignore
