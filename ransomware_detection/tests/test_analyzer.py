from src.analyzer import Analyzer


def print_report(filename, result, features):
    print()
    print("=" * 40)
    print("        RANSOMWARE RISK ANALYZER")
    print("=" * 40)

    print()
    print(f"File: {filename}")

    print()
    print("Features")
    print("-" * 40)

    print(f"Entropy:                    {features['entropy']:.2f}")
    print(
        f"YARA matches:               "
        f"{features['yara_match_count']}"
    )

    extension = (
        "YES"
        if features["suspicious_extension"]
        else "NO"
    )

    print(
        f"Suspicious extension:       "
        f"{extension}"
    )

    print(
        f"Threat intelligence:        "
        f"{features['threat_intelligence_score']:.2f}"
    )

    print(
        f"ML probability:             "
        f"{result['ml_probability']:.2%}"
    )

    print()
    print("FINAL ASSESSMENT")
    print("-" * 40)

    print(
        f"Risk score:                 "
        f"{result['risk_score']:.0f}/100"
    )

    print(
        f"Risk level:                 "
        f"{result['risk_level']}"
    )

    print()
    print("Reasons:")

    for reason in result["reasons"]:
        print(f"  • {reason}")

    print()
    print("=" * 40)


def main():

    analyzer = Analyzer()

    # Safe synthetic test data.
    features = {
        "file_size": 250000,
        "entropy": 7.82,
        "suspicious_extension": 1,
        "yara_match_count": 2,
        "threat_intelligence_score": 0.90
    }

    result = analyzer.analyze(features)

    print_report(
        "example.txt",
        result,
        features
    )


if __name__ == "__main__":
    main()