from src.hash_utils import calculate_sha256
from src.threat_intelligence import ThreatIntelligence


file_path = "test_files/normal.txt"

dataset_path = "data/threat_intelligence.csv"


print("\n==============================")
print("THREAT INTELLIGENCE ANALYSIS")
print("==============================")


file_hash = calculate_sha256(
    file_path
)


print(
    "\nCalculated SHA-256:"
)

print(file_hash)


ti = ThreatIntelligence(
    dataset_path
)


matches = ti.lookup(
    file_hash
)


if matches:

    print(
        "\nKnown threat indicator detected!"
    )

    for match in matches:

        print(
            "Threat family:",
            match["threat_family"]
        )

        print(
            "Severity:",
            match["severity"]
        )

        print(
            "Confidence:",
            match["confidence"]
        )

else:

    print(
        "\nNo matching threat-intelligence indicator."
    )


score = ti.get_threat_score(
    file_hash
)


print(
    "\nThreat intelligence score:",
    score
)


print("==============================")