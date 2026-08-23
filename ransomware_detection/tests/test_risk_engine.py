from src.risk_engine import RiskEngine


engine = RiskEngine()


print("\n==============================")
print("RISK ENGINE TEST")
print("==============================")


# Synthetic high-risk example.

result = engine.calculate(

    ml_probability=0.90,

    entropy=7.8,

    yara_match_count=2,

    suspicious_extension=1,

    threat_intelligence_score=0.90
)


print(
    "\nRisk score:",
    result.score
)


print(
    "Risk level:",
    result.level
)


print("\nReasons:")

for reason in result.reasons:

    print(
        "-",
        reason
    )


print("==============================")