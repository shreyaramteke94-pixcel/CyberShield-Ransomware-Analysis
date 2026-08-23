from src.hash_utils import calculate_sha256


file_path = "test_files/normal.txt"


file_hash = calculate_sha256(
    file_path
)


print("\n==============================")
print("SHA-256")
print("==============================")


print(
    "File:",
    file_path
)


print(
    "SHA-256:",
    file_hash
)


print("==============================")