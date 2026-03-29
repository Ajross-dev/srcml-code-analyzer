from __future__ import annotations

import re
import xml.etree.ElementTree as ET
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

BAD_VARIABLE_NAMES = {
    "temp", "tmp", "foo", "bar", "thing", "stuff", "data", "var", "value", "test"
}

CONTROL_TAGS = {"if", "for", "while", "switch", "do", "elseif"}


def make_finding(
    *,
    issue: str,
    severity: str,
    explanation: str,
    suggestion: str,
    function: str = "",
    line: int | str | None = None
) -> Dict[str, Any]:
    return {
        "issue": issue,
        "severity": severity,
        "explanation": explanation,
        "suggestion": suggestion,
        "function": function,
        "line": line if line is not None else "Unknown"
    }


def strip_namespace(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def get_start_line(node: ET.Element) -> int | None:
    for key, value in node.attrib.items():
        key_lower = key.lower()
        if "start" in key_lower or "line" in key_lower:
            match = re.match(r"(\d+)", str(value))
            if match:
                return int(match.group(1))
    return None


def looks_like_risky_scanf(call_text: str) -> bool:
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


def strip_comments_and_strings(code: str) -> str:
    code = re.sub(r'//.*', '', code)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', code)
    code = re.sub(r"'(?:\\.|[^'\\])*'", "''", code)
    return code


def count_comment_lines(code: str) -> int:
    count = 0
    in_block = False

    for line in code.splitlines():
        stripped = line.strip()

        if in_block:
            count += 1
            if "*/" in stripped:
                in_block = False
            continue

        if stripped.startswith("//"):
            count += 1
        elif "/*" in stripped:
            count += 1
            if "*/" not in stripped:
                in_block = True

    return count


def function_has_nearby_comment(code_lines: List[str], start_line: int | None) -> bool:
    if start_line is None:
        return False

    idx = start_line - 1
    for offset in range(1, 4):
        look_idx = idx - offset
        if look_idx < 0:
            break
        stripped = code_lines[look_idx].strip()
        if not stripped:
            continue
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.endswith("*/"):
            return True
        break

    return False


def check_bad_variable_names(variables: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for variable in variables:
        name = str(variable.get("name", "")).strip()
        line = variable.get("line", "Unknown")

        if not name:
            continue

        if name in BAD_VARIABLE_NAMES:
            findings.append(make_finding(
                issue=f"Vague variable name detected: {name}",
                severity="Low",
                explanation=(
                    f"The variable name '{name}' is too generic and may make the code harder to read."
                ),
                suggestion="Use a more descriptive variable name that explains its purpose.",
                function="variable-analysis",
                line=line
            ))
        elif len(name) == 1 and name not in {"i", "j", "k"}:
            findings.append(make_finding(
                issue=f"Very short variable name detected: {name}",
                severity="Low",
                explanation=(
                    f"The variable name '{name}' is very short and may reduce readability outside simple loop counters."
                ),
                suggestion="Use a longer, descriptive variable name unless this is a simple loop index.",
                function="variable-analysis",
                line=line
            ))

    return findings


def check_long_functions(functions: List[Dict[str, Any]], code_lines: List[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for func in functions:
        name = func.get("name", "unknown")
        start_line = func.get("start_line")
        end_line = func.get("end_line")
        length_estimate = int(func.get("length_estimate", 0) or 0)

        if length_estimate > 35:
            findings.append(make_finding(
                issue=f"Function may be too long: {name}()",
                severity="Low",
                explanation=(
                    "Long functions can reduce readability, increase complexity, and make debugging harder."
                ),
                suggestion="Break large functions into smaller helper functions with focused responsibilities.",
                function=name,
                line=start_line or "Unknown"
            ))

        if length_estimate > 12 and not function_has_nearby_comment(code_lines, start_line):
            findings.append(make_finding(
                issue=f"Low function documentation: {name}()",
                severity="Low",
                explanation=(
                    "This function is moderately large but does not appear to have a nearby explanatory comment."
                ),
                suggestion="Add a short comment above the function describing what it does and why.",
                function=name,
                line=start_line or "Unknown"
            ))

        if start_line and end_line and end_line >= start_line:
            header = "\n".join(code_lines[start_line - 1:min(end_line, start_line + 2)])
            param_match = re.search(r"\((.*?)\)", header, re.DOTALL)
            if param_match:
                params = [p.strip() for p in param_match.group(1).split(",") if p.strip()]
                if len(params) > 4:
                    findings.append(make_finding(
                        issue=f"Too many parameters in function: {name}()",
                        severity="Low",
                        explanation=(
                            f"This function appears to take {len(params)} parameters, which may make it harder to use and maintain."
                        ),
                        suggestion="Consider grouping related parameters into a struct or class.",
                        function=name,
                        line=start_line
                    ))

    return findings


def walk_nesting(node: ET.Element, depth: int = 0) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    tag = strip_namespace(node.tag)

    next_depth = depth
    if tag in CONTROL_TAGS:
        next_depth += 1
        if next_depth > 3:
            findings.append(make_finding(
                issue="Deep nesting detected",
                severity="Medium",
                explanation=(
                    f"Control-flow nesting reached depth {next_depth}, which may hurt readability and increase complexity."
                ),
                suggestion="Flatten nested logic with guard clauses or helper functions.",
                function=tag,
                line=get_start_line(node) or "Unknown"
            ))

    for child in node:
        findings.extend(walk_nesting(child, next_depth))

    return findings


def check_deep_nesting(root: ET.Element) -> List[Dict[str, Any]]:
    return walk_nesting(root, 0)


def check_low_comments(code: str, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    stripped_lines = [line for line in code.splitlines() if line.strip()]
    total_lines = len(stripped_lines)
    comment_lines = count_comment_lines(code)

    if total_lines == 0:
        return findings

    ratio = comment_lines / total_lines

    if comment_lines == 0:
        findings.append(make_finding(
            issue="No comments or documentation detected",
            severity="Medium",
            explanation=(
                "The submitted code does not appear to contain any comments, which can make maintenance harder."
            ),
            suggestion="Add short comments for important logic and document non-obvious functions.",
            function="file-level",
            line=1
        ))
    elif ratio < 0.05 and len(functions) >= 2:
        findings.append(make_finding(
            issue="Low overall documentation density",
            severity="Low",
            explanation=(
                "The file contains very few comments relative to its size."
            ),
            suggestion="Add comments where the intent or logic is not immediately obvious.",
            function="file-level",
            line=1
        ))

    return findings


def check_unused_variables(code: str, variables: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    cleaned = strip_comments_and_strings(code)

    for variable in variables:
        name = str(variable.get("name", "")).strip()
        line = variable.get("line", "Unknown")

        if not name:
            continue

        occurrences = len(re.findall(rf"\b{re.escape(name)}\b", cleaned))
        if occurrences <= 1:
            findings.append(make_finding(
                issue=f"Likely unused variable: {name}",
                severity="Low",
                explanation=(
                    f"The variable '{name}' appears only once and may be unused."
                ),
                suggestion="Remove the variable if unnecessary, or use it meaningfully.",
                function="variable-analysis",
                line=line
            ))

    return findings


def has_zero_guard(var_name: str, nearby_lines: List[str]) -> bool:
    guard_patterns = [
        rf"\b{re.escape(var_name)}\s*!=\s*0\b",
        rf"\b{re.escape(var_name)}\s*>\s*0\b",
        rf"\b{re.escape(var_name)}\s*<\s*0\b",
        rf"\b{re.escape(var_name)}\b\s*\?",
        rf"\bif\s*\([^)]*\b{re.escape(var_name)}\b[^)]*\)"
    ]

    joined = "\n".join(nearby_lines)
    return any(re.search(pattern, joined) for pattern in guard_patterns)


def check_division_by_zero(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.splitlines()

    for i, raw_line in enumerate(lines, start=1):
        line = re.sub(r'//.*', '', raw_line)

        if re.search(r'/\s*0\b', line) or re.search(r'%\s*0\b', line):
            findings.append(make_finding(
                issue="Definite division by zero detected",
                severity="High",
                explanation=(
                    "A literal zero appears as a divisor or modulo operand, which will cause undefined or invalid behavior."
                ),
                suggestion="Ensure the denominator is never zero before division or modulo.",
                function="arithmetic-check",
                line=i
            ))
            continue

        match = re.search(r'[/%]\s*([A-Za-z_]\w*)', line)
        if match:
            denominator = match.group(1)
            nearby_start = max(0, i - 3)
            nearby_end = min(len(lines), i + 2)
            nearby_lines = lines[nearby_start:nearby_end]

            if not has_zero_guard(denominator, nearby_lines):
                findings.append(make_finding(
                    issue=f"Possible division-by-zero risk: {denominator}",
                    severity="Low",
                    explanation=(
                        f"The code divides by '{denominator}', but no nearby zero-check was clearly detected."
                    ),
                    suggestion=f"Check that '{denominator}' is not zero before division.",
                    function="arithmetic-check",
                    line=i
                ))

    return findings


def normalize_line(line: str) -> str:
    line = re.sub(r'//.*', '', line)
    line = line.strip()
    if not line:
        return ""
    if line in {"{", "}", ";"}:
        return ""
    line = re.sub(r'\s+', ' ', line)
    return line


def check_duplicate_code(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.splitlines()

    normalized = [normalize_line(line) for line in lines]
    windows: Dict[str, List[int]] = {}

    for i in range(len(normalized) - 2):
        block = normalized[i:i + 3]
        if any(not part for part in block):
            continue

        key = "\n".join(block)
        windows.setdefault(key, []).append(i + 1)

    for _, locations in windows.items():
        if len(locations) >= 2:
            findings.append(make_finding(
                issue="Duplicate code pattern detected",
                severity="Low",
                explanation=(
                    f"A similar 3-line code block appears multiple times, starting near lines {locations[:3]}."
                ),
                suggestion="Extract repeated logic into a helper function to reduce duplication.",
                function="duplication-check",
                line=locations[0]
            ))
            break

    return findings


def check_magic_numbers(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = code.splitlines()

    allowed = {"0", "1", "-1", "2"}

    for i, raw_line in enumerate(lines, start=1):
        line = re.sub(r'//.*', '', raw_line)

        for number in re.findall(r'(?<![\w.])-?\d+(?![\w.])', line):
            if number in allowed:
                continue

            if re.search(r'\b(case|return)\b', line):
                continue

            findings.append(make_finding(
                issue=f"Magic number detected: {number}",
                severity="Low",
                explanation=(
                    f"The literal value {number} appears directly in code and may reduce readability."
                ),
                suggestion="Consider replacing repeated or meaningful numeric literals with named constants.",
                function="style-check",
                line=i
            ))
            break

    return findings


def check_code_smells(
    functions: List[Dict[str, Any]],
    calls: List[Dict[str, Any]],
    variables: List[Dict[str, Any]],
    code: str,
    root: ET.Element
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    code_lines = code.splitlines()

    findings.extend(check_long_functions(functions, code_lines))
    findings.extend(check_bad_variable_names(variables))
    findings.extend(check_low_comments(code, functions))
    findings.extend(check_unused_variables(code, variables))
    findings.extend(check_division_by_zero(code))
    findings.extend(check_duplicate_code(code))
    findings.extend(check_magic_numbers(code))
    findings.extend(check_deep_nesting(root))

    dangerous_names = {"gets", "strcpy", "strcat", "sprintf", "vsprintf", "system"}
    risky_count = sum(1 for call in calls if call.get("function") in dangerous_names)

    if risky_count >= 3:
        findings.append(make_finding(
            issue="Multiple dangerous library calls detected",
            severity="Medium",
            explanation=(
                "The file contains several risky C/C++ library calls, which raises the overall chance of memory safety or command execution problems."
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