
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from pathlib import Path
from uuid import uuid4

from analyzer import (
    calculate_hashes,
    inspect_strings,
    analyze_pe,
    assess_risk
)

app = Flask(__name__)

UPLOAD_FOLDER = Path("uploads")
UPLOAD_FOLDER.mkdir(exist_ok=True)

# Maximum upload size: 16 MB
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    error = None

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if not uploaded_file or not uploaded_file.filename:
            error = "Please select a file first."

        else:
            filename = secure_filename(uploaded_file.filename)

            if not filename:
                error = "Invalid filename."

            else:
                file_path = UPLOAD_FOLDER / (
                    f"{uuid4().hex}_{filename}"
                )

                try:
                    uploaded_file.save(file_path)

                    # FEATURE 1: Hash Analysis
                    result = calculate_hashes(file_path)

                    # FEATURE 2: String Inspection
                    result["inspection"] = inspect_strings(file_path)

                    # FEATURE 3: PE File Analysis
                    result["pe_analysis"] = analyze_pe(file_path)

                    # FEATURE 4: Malware Risk Assessment
                    result["risk_assessment"] = assess_risk(
                        result["inspection"],
                        result["pe_analysis"]
                    )

                except OSError:
                    error = (
                        "Unable to read or analyze the uploaded file."
                    )
                    result = None

                except Exception:
                    app.logger.exception("File analysis failed.")
                    error = (
                        "An unexpected error occurred during analysis. "
                        "Check the VS Code terminal for details."
                    )
                    result = None

                finally:
                    try:
                        if file_path.exists():
                            file_path.unlink()
                    except OSError:
                        app.logger.warning(
                            "Could not remove temporary uploaded file."
                        )

    return render_template(
        "index.html",
        result=result,
        error=error
    )


@app.errorhandler(413)
def file_too_large(error):
    return render_template(
        "index.html",
        result=None,
        error="File is too large. Please upload a file under 16 MB."
    ), 413


if __name__ == "__main__":
    app.run(debug=True)
