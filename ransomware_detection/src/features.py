import math
import os


def add_threat_intelligence_features(
        features,
        threat_score
):
    features[
        "threat _intelligence_score"
    ] =threat_score
    return features    



def extract_features(
    file_path,
    yara_matches,
    entropy
):

    file_size = os.path.getsize(
        file_path
    )

    extension = os.path.splitext(
        file_path
    )[1].lower()


    suspicious_extensions = [
        ".locked",
        ".encrypted",
        ".enc",
        ".vault",
        ".crypt"
    ]


    suspicious_extension = (
        1
        if extension in suspicious_extensions
        else 0
    )


    yara_match_count = len(
        yara_matches
    )


    return {

        "file_size": file_size,

        "log_file_size": math.log1p(
            file_size
        ),

        "entropy": entropy,

        "suspicious_extension":
            suspicious_extension,

        "yara_match_count":
            yara_match_count
    }