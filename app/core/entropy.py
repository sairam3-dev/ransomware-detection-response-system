
import math
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a sequence of bytes.

    Returns a value between 0.0 and 8.0.
    """
    if not data:
        return 0.0

    total_bytes = len(data)
    byte_counts = Counter(data)
    entropy = 0.0

    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_file_entropy(file_path: str) -> float:
    """Calculate entropy using the first 64 KB of a file."""
    with open(file_path, "rb") as file:
        sample = file.read(64 * 1024)

    return calculate_entropy(sample)

