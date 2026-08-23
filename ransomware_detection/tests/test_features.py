from src.yara_scanner import scan_file
from src.features import extract_features


file_path = "test_files/yara_test.txt"

rule_path = "rules/ransomware.yar"


yara_results = scan_file(
    file_path,
    rule_path
)


features = extract_features(
    file_path,
    yara_results
)


print("\n==============================")
print("FEATURE EXTRACTION")
print("==============================")


for name, value in features.items():

    print(
        f"{name}: {value}"
    )


print("==============================")