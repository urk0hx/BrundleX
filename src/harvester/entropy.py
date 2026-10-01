"""
Shannon Entropy Gatekeeper.
Calculates Shannon entropy to detect packed or encrypted malware binaries.
Samples exceeding the threshold (default H > 7.1) are rejected to prevent crypter contamination.
"""

import collections
import math


def calculate_entropy(data: bytes | bytearray) -> float:
    """
    Computes Shannon entropy H(X) = -sum(p_i * log2(p_i)) over the byte sequence.
    Returns 0.0 for empty input.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Expected bytes or bytearray, got {type(data).__name__}")

    if not data:
        return 0.0

    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0

    for count in counts.values():
        p_i = count / length
        entropy -= p_i * math.log2(p_i)

    return entropy


def is_sample_packed(data: bytes | bytearray, threshold: float = 7.1) -> bool:
    """
    Checks if binary data appears packed/encrypted based on Shannon entropy.
    Returns True if entropy strictly exceeds the threshold.
    """
    return calculate_entropy(data) > threshold
