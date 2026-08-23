from src.yara_scanner import scan_file


file_path = "test_files/yara_test.txt"

rule_path = "rules/ransomware.yar"


results = scan_file(
    file_path,
    rule_path
)


print("\n==============================")
print("YARA ANALYSIS")
print("==============================")


print(
    "File:",
    file_path
)


if results:

    print("\nYARA MATCHES:")

    for result in results:

        print(
            "Rule:",
            result["rule"]
        )

        print(
            "Namespace:",
            result["namespace"]
        )

else:

    print(
        "\nNo YARA rules matched."
    )


print("==============================")