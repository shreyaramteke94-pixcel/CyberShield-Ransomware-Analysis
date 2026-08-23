import math
from collections import Counter


def calculate_entropy(file_path):
    """
    Calculate Shannon entropy of a file.

    The function only READS the file.
    It does not modify or execute it.

    Returns:
        float: entropy value between 0 and 8
    """

    counter = Counter()
    total_bytes = 0

    # Read the file in small chunks
    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            counter.update(chunk)

            total_bytes += len(chunk)

    # Empty file
    if total_bytes == 0:
        return 0.0

    entropy = 0.0

    # Shannon entropy calculation
    for count in counter.values():

        probability = count / total_bytes

        entropy -= (
            probability *
            math.log2(probability)
        )

    return round(entropy, 4)


def entropy_level(entropy):
    """
    Convert entropy value into a simple category.
    """

    if entropy < 4:
        return "LOW"

    elif entropy < 6:
        return "MEDIUM"

    elif entropy < 7.5:
        return "HIGH"

    else:
        return "VERY HIGH"