from pathlib import Path
import uuid

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
)

from src.analyzer import Analyzer
from src.file_features import extract_features


app = Flask(__name__)


# Maximum upload size: 10 MB.
app.config["MAX_CONTENT_LENGTH"] = (
    10 * 1024 * 1024
)


UPLOAD_FOLDER = Path("uploads")

UPLOAD_FOLDER.mkdir(
    exist_ok=True
)


# Load the existing Module 6/7 analyzer.
analyzer = Analyzer()


@app.route("/")
def index():

    return render_template(
        "index.html"
    )


@app.route(
    "/api/analyze",
    methods=["POST"]
)
def analyze_file():

    if "file" not in request.files:

        return jsonify({
            "error":
                "No file was uploaded."
        }), 400


    uploaded_file = request.files["file"]


    if not uploaded_file.filename:

        return jsonify({
            "error":
                "No filename supplied."
        }), 400


    # Read file as data.
    # Nothing is executed.

    data = uploaded_file.read()


    if not data:

        return jsonify({
            "error":
                "The uploaded file is empty."
        }), 400


    temporary_path = (
        UPLOAD_FOLDER
        / f"{uuid.uuid4().hex}.upload"
    )


    try:

        # Temporary storage only.
        temporary_path.write_bytes(data)


        features = extract_features(
            uploaded_file.filename,
            data
        )


        result = analyzer.analyze(
            features
        )


        return jsonify({

            "success": True,

            "filename":
                uploaded_file.filename,

            "sha256":
                features["sha256"],

            "file_size":
                features["file_size"],

            "entropy":
                round(
                    features["entropy"],
                    4
                ),

            "yara_matches":
                features[
                    "yara_match_count"
                ],

            "suspicious_extension":
                bool(
                    features[
                        "suspicious_extension"
                    ]
                ),

            "threat_intelligence_score":
                features[
                    "threat_intelligence_score"
                ],

            "ml_probability":
                round(
                    result[
                        "ml_probability"
                    ],
                    4
                ),

            "risk_score":
                result["risk_score"],

            "risk_level":
                result["risk_level"],

            "reasons":
                result["reasons"],
        })


    except Exception as exc:

        print(
            "Analysis error:",
            repr(exc)
        )

        return jsonify({
            "error":
                "Analysis failed. "
                "Check the terminal."
        }), 500


    finally:

        # Remove temporary upload.
        try:

            temporary_path.unlink(
                missing_ok=True
            )

        except Exception:

            pass


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )