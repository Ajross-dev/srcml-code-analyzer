from __future__ import annotations

import re
from typing import Any, Dict, List

from flask import Flask, jsonify, render_template, request

from analyzer import analyze_code_text

app = Flask(__name__)


def count_lines(code: str) -> int:
    if not code.strip():
        return 0
    return len(code.splitlines())


def count_comments(code: str) -> int:
    """
    Count simple C++ comment markers.
    """
    if not code.strip():
        return 0

    count = 0
    for line in code.splitlines():
        if "//" in line:
            count += 1
        if "/*" in line:
            count += 1
    return count


def looks_like_cpp(code: str) -> bool:
    """
    Lightweight heuristic check for obvious C++ input.
    srcML still does the real parsing.
    """
    if not code or not code.strip():
        return False

    cpp_markers = [
        r"#include\s*<",
        r'#include\s*"',
        r"\bstd::",
        r"\busing\s+namespace\s+std\b",
        r"\bint\s+main\s*\(",
        r"\bcout\s*<<",
        r"\bcin\s*>>",
        r"\bclass\s+\w+",
        r"\btemplate\s*<",
        r"\bnamespace\s+\w+",
        r"\bvector\s*<",
        r"\bstring\s+\w+",
        r"\bpublic\s*:",
        r"\bprivate\s*:",
        r"\bprotected\s*:",
        r"::",
    ]

    for pattern in cpp_markers:
        if re.search(pattern, code):
            return True

    if re.search(r"\b[a-zA-Z_]\w*\s+[a-zA-Z_]\w*\s*\([^)]*\)\s*\{", code):
        return True

    return False


def determine_risk_level(score: int, findings_count: int) -> str:
    if findings_count >= 5 or score < 50:
        return "High"
    if findings_count >= 2 or score < 80:
        return "Moderate"
    return "Low"


def build_summary(score: int, findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return (
            "No major insecure C++ patterns were detected by the current rule set. "
            "The analyzer did not find flagged calls or risky input usage."
        )

    high_count = sum(1 for item in findings if item.get("severity") == "High")
    medium_count = sum(1 for item in findings if item.get("severity") == "Medium")
    low_count = sum(1 for item in findings if item.get("severity") == "Low")

    return (
        f"The analyzer found {len(findings)} issue(s) in the submitted C++ code. "
        f"Security score: {score}%. "
        f"High: {high_count}, Medium: {medium_count}, Low: {low_count}."
    )


def extract_suggestions(findings: List[Dict[str, Any]]) -> List[str]:
    suggestions: List[str] = []
    seen = set()

    for finding in findings:
        suggestion = finding.get("suggestion")
        if suggestion and suggestion not in seen:
            suggestions.append(suggestion)
            seen.add(suggestion)

    if not suggestions:
        suggestions.append("No remediation suggestions were generated.")
    return suggestions


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/results", methods=["GET"])
def results_page():
    return render_template("results.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "srcAnalyzer backend",
        "language": "C++ only"
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        payload = request.get_json(silent=True)

        code = ""
        if isinstance(payload, dict):
            code = payload.get("code", "")
        else:
            code = request.form.get("code", "")

        if not code or not code.strip():
            return jsonify({
                "success": False,
                "error": "No code was provided for analysis."
            }), 400

        if not looks_like_cpp(code):
            return jsonify({
                "success": False,
                "error": "Only C++ code is supported right now."
            }), 400

        analysis_results = analyze_code_text(code)

        findings = analysis_results.get("findings", [])
        score = int(analysis_results.get("score", 100))
        line_count = count_lines(code)
        comment_count = count_comments(code)
        risk_level = determine_risk_level(score, len(findings))
        summary = build_summary(score, findings)
        suggestions = extract_suggestions(findings)

        return jsonify({
            "success": True,
            "language": "C++",
            "summary": summary,
            "issueCount": len(findings),
            "lineCount": line_count,
            "commentCount": comment_count,
            "score": score,
            "riskLevel": risk_level,
            "issues": findings,
            "suggestions": suggestions,
            "codePreview": code
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


if __name__ == "__main__":
    app.run(debug=True)