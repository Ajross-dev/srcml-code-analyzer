from __future__ import annotations

import re
from typing import Any, Dict, List


DANGEROUS_FUNCTIONS: Dict[str, Dict[str, str]] = {
    "gets": {
        "severity": "High",
        "issue": "Dangerous function detected: gets()",
        "explanation": "gets() performs no bounds checking and can cause buffer overflow.",
        "suggestion": "Replace gets() with std::getline() or a bounded input approach."
    },
    "strcpy": {
        "severity": "High",
        "issue": "Unsafe copy detected: strcpy()",
        "explanation": "strcpy() can overflow the destination buffer if the source is too large.",
        "suggestion": "Use safer string handling such as std::string or a bounded copy routine."
    },
    "strcat": {
        "severity": "High",
        "issue": "Unsafe concatenation detected: strcat()",
        "explanation": "strcat() may overflow the destination buffer during concatenation.",
        "suggestion": "Use std::string concatenation instead of strcat()."
    },
    "sprintf": {
        "severity": "High",
        "issue": "Unsafe formatting detected: sprintf()",
        "explanation": "sprintf() does not limit output size and may overflow the buffer.",
        "suggestion": "Use snprintf() or safer C++ formatting methods."
    },
    "vsprintf": {
        "severity": "High",
        "issue": "Unsafe formatting detected: vsprintf()",
        "explanation": "vsprintf() does not enforce a maximum buffer size.",
        "suggestion": "Use vsnprintf() or safer formatting alternatives."
    },
    "system": {
        "severity": "High",
        "issue": "Command execution detected: system()",
        "explanation": "system() can introduce command injection risk and should be avoided when possible.",
        "suggestion": "Avoid system(); use safer APIs or tightly controlled command handling."
    },
    "scanf": {
        "severity": "Medium",
        "issue": "Potentially unsafe input detected: scanf()",
        "explanation": "scanf() can be unsafe if width specifiers are not used for string inputs.",
        "suggestion": "Use width-limited formats or prefer C++ input APIs such as std::cin or std::getline."
    },
    "fscanf": {
        "severity": "Medium",
        "issue": "Potentially unsafe input detected: fscanf()",
        "explanation": "fscanf() can be unsafe if width specifiers are missing for string reads.",
        "suggestion": "Use width limits or safer parsing logic."
    }
}


SEVERITY_PENALTY = {
    "High": 20,
    "Medium": 10,
    "Low": 5
}


def make_finding(
    *,
    issue: str,
    severity: str,
    explanation: str,
    suggestion: str,
    function: str = "",
    line: str | None = None
) -> Dict[str, Any]:
    return {
        "issue": issue,
        "severity": severity,
        "explanation": explanation,
        "suggestion": suggestion,
        "function": function,
        "line": line if line is not None else "Unknown"
    }


def looks_like_risky_scanf(call_text: str) -> bool:
    """
    Flag scanf/fscanf with %s and no width limit.
    Example risky: scanf("%s", buf);
    Example safer: scanf("%9s", buf);
    """
    if not call_text:
        return False

    if "%s" in call_text:
        if re.search(r"%\d+s", call_text):
            return False
        return True

    return False


def check_dangerous_calls(calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for call in calls:
        function_name = call.get("function", "").strip()
        text = call.get("text", "")
        line = call.get("line")

        if function_name in DANGEROUS_FUNCTIONS:
            rule = DANGEROUS_FUNCTIONS[function_name]

            if function_name in {"scanf", "fscanf"}:
                if looks_like_risky_scanf(text):
                    findings.append(make_finding(
                        issue=rule["issue"],
                        severity=rule["severity"],
                        explanation=(
                            rule["explanation"] +
                            " This call appears to read formatted input in a risky way."
                        ),
                        suggestion=rule["suggestion"],
                        function=function_name,
                        line=line
                    ))
                continue

            findings.append(make_finding(
                issue=rule["issue"],
                severity=rule["severity"],
                explanation=rule["explanation"],
                suggestion=rule["suggestion"],
                function=function_name,
                line=line
            ))

    return findings


def check_code_smells(
    functions: List[Dict[str, Any]],
    calls: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for func in functions:
        name = func.get("name", "unknown")
        length_estimate = func.get("length_estimate", 0)
        line = func.get("line")

        if length_estimate > 40:
            findings.append(make_finding(
                issue=f"Function may be too long: {name}()",
                severity="Low",
                explanation=(
                    "Long functions can reduce readability, maintainability, "
                    "and make security review harder."
                ),
                suggestion="Break large functions into smaller helper functions.",
                function=name,
                line=line
            ))

    dangerous_names = {"gets", "strcpy", "strcat", "sprintf", "vsprintf", "system"}
    risky_count = sum(1 for call in calls if call.get("function") in dangerous_names)

    if risky_count >= 3:
        findings.append(make_finding(
            issue="Multiple dangerous library calls detected",
            severity="Medium",
            explanation=(
                "The file contains several risky C/C++ library calls, which raises the "
                "overall chance of memory safety or command execution problems."
            ),
            suggestion="Replace dangerous C-style routines with safer C++ abstractions.",
            function="multiple",
            line="Unknown"
        ))

    return findings


def calculate_score(findings: List[Dict[str, Any]]) -> int:
    score = 100

    for finding in findings:
        severity = finding.get("severity", "Low")
        score -= SEVERITY_PENALTY.get(severity, 5)

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    return score