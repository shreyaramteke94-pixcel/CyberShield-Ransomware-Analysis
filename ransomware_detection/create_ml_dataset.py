import random
import csv


random.seed(42)


OUTPUT_FILE = "data/ml_dataset.csv"

NUM_SAMPLES = 1000


fieldnames = [
    "file_size",
    "entropy",
    "suspicious_extension",
    "yara_match_count",
    "threat_intelligence_score",
    "label"
]


rows = []


for _ in range(NUM_SAMPLES):

    # Generate harmless synthetic features.
    file_size = random.randint(
        1_000,
        10_000_000
    )

    entropy = round(
        random.uniform(2.0, 8.0),
        3
    )

    suspicious_extension = random.choice(
        [0, 1]
    )

    yara_match_count = random.randint(
        0,
        4
    )

    threat_intelligence_score = round(
        random.uniform(0.0, 1.0),
        3
    )


    # Synthetic labeling rule.
    #
    # This is NOT a real ransomware detector.
    # It only creates training data for demonstrating
    # the ML pipeline.

    risk_points = 0


    if entropy >= 7.0:
        risk_points += 2


    if suspicious_extension == 1:
        risk_points += 2


    if yara_match_count >= 1:
        risk_points += 2


    if threat_intelligence_score >= 0.7:
        risk_points += 3


    if risk_points >= 4:
        label = 1

    else:
        label = 0


    rows.append({
        "file_size": file_size,
        "entropy": entropy,
        "suspicious_extension": suspicious_extension,
        "yara_match_count": yara_match_count,
        "threat_intelligence_score":
            threat_intelligence_score,
        "label": label
    })


with open(
    OUTPUT_FILE,
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )

    writer.writeheader()

    writer.writerows(rows)


print(
    f"Created {NUM_SAMPLES} synthetic samples."
)

print(
    f"Saved to: {OUTPUT_FILE}"
)