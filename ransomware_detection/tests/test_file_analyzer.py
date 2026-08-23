from src.file_analyzer import analyze_file


file_path = "test_files/sample.txt"


result = analyze_file(
    file_path
)


print("\n==============================")
print("FILE ANALYSIS RESULT")
print("==============================")


print(
    "File Name:",
    result["file_name"]
)

print(
    "File Size:",
    result["file_size"],
    "bytes"
)

print(
    "Extension:",
    result["extension"]
)

print(
    "MIME Type:",
    result["mime_type"]
)

print(
    "SHA-256:",
    result["sha256"]
)
print(
    "Entropy:",
    result["entropy"]
)