from src.entropy import (
    calculate_entropy,
    entropy_level
)


file_path = "test_files/sample.txt"


entropy = calculate_entropy(
    file_path
)


level = entropy_level(
    entropy
)


print("\n==============================")
print("ENTROPY ANALYSIS")
print("==============================")


print(
    "File:",
    file_path
)


print(
    "Entropy:",
    entropy
)


print(
    "Entropy Level:",
    level
)


print("==============================")
