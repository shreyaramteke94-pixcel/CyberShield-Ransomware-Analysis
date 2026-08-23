from src.threat_intelligence import ThreatIntelligence


dataset_path = "data/threat_intelligence.csv"


ti = ThreatIntelligence(
    dataset_path
)


print("\n==============================")
print("THREAT INTELLIGENCE TEST")
print("==============================")


indicator = "DEMO_HASH_001"


results = ti.lookup(
    indicator
)


if results:

    print(
        "\nIndicator found!"
    )

    for result in results:

        print(
            "Indicator:",
            result["indicator"]
        )

        print(
            "Type:",
            result["indicator_type"]
        )

        print(
            "Threat family:",
            result["threat_family"]
        )

        print(
            "Severity:",
            result["severity"]
        )

        print(
            "Confidence:",
            result["confidence"]
        )

        print(
            "Source:",
            result["source"]
        )

else:

    print(
        "\nIndicator not found."
    )


score = ti.get_threat_score(
    indicator
)


print(
    "\nThreat score:",
    score
)


print("==============================")
