# rules.py
# Defines security rules and detection logic for srcAnalyzer

from lxml import etree

# -----------------------------
# Rule Definitions
# -----------------------------

UNSAFE_FUNCTIONS = [
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "scanf",
    "fscanf",
    "sscanf"
]

SAFE_ALTERNATIVES = {
    "gets": "fgets",
    "strcpy": "strncpy",
    "strcat": "strncat",
    "sprintf": "snprintf",
    "scanf": "scanf_s"
}

# -----------------------------
# Helper Functions
# -----------------------------

def get_function_calls(xml_root):
    """Extract all function calls from srcML XML."""
    calls = []
    for call in xml_root.findall(".//call"):
        name_elem = call.find(".//name")
        if name_elem is not None:
            calls.append((name_elem.text, call))
    return calls


def get_array_accesses(xml_root):
    """Extract array access patterns."""
    return xml_root.findall(".//index")


# -----------------------------
# Rule Checks
# -----------------------------

def check_unsafe_functions(xml_root):
    findings = []

    for func_name, node in get_function_calls(xml_root):
        if func_name in UNSAFE_FUNCTIONS:
            findings.append({
                "type": "Unsafe Function",
                "function": func_name,
                "message": f"Use of unsafe function '{func_name}' detected.",
                "suggestion": f"Consider using '{SAFE_ALTERNATIVES.get(func_name, 'safer alternative')}' instead.",
                "severity": "High"
            })

    return findings


def check_buffer_overflow_risk(xml_root):
    findings = []

    for func_name, node in get_function_calls(xml_root):
        if func_name in ["strcpy", "strcat", "sprintf"]:
            findings.append({
                "type": "Buffer Overflow Risk",
                "function": func_name,
                "message": f"'{func_name}' may cause buffer overflow if input is not bounded.",
                "suggestion": "Use bounded versions like strncpy, strncat, or snprintf.",
                "severity": "High"
            })

    return findings


def check_unbounded_input(xml_root):
    findings = []

    for func_name, node in get_function_calls(xml_root):
        if func_name in ["scanf", "gets"]:
            findings.append({
                "type": "Unbounded Input",
                "function": func_name,
                "message": f"'{func_name}' does not limit input size.",
                "suggestion": "Always specify input size limits or use safer alternatives.",
                "severity": "Medium"
            })

    return findings


def check_array_indexing(xml_root):
    findings = []

    indexes = get_array_accesses(xml_root)
    for idx in indexes:
        findings.append({
            "type": "Array Access",
            "message": "Array indexing detected. Ensure bounds checking is implemented.",
            "suggestion": "Validate indices before accessing arrays.",
            "severity": "Low"
        })

    return findings


# -----------------------------
# Scoring System
# -----------------------------

def calculate_score(findings):
    score = 100

    for f in findings:
        if f["severity"] == "High":
            score -= 20
        elif f["severity"] == "Medium":
            score -= 10
        elif f["severity"] == "Low":
            score -= 5

    return max(score, 0)


# -----------------------------
# Main Analyzer Entry
# -----------------------------

def analyze(xml_content):
    """
    Main function to analyze srcML XML content.
    Returns findings and security score.
    """

    xml_root = etree.fromstring(xml_content)

    findings = []
    findings.extend(check_unsafe_functions(xml_root))
    findings.extend(check_buffer_overflow_risk(xml_root))
    findings.extend(check_unbounded_input(xml_root))
    findings.extend(check_array_indexing(xml_root))

    score = calculate_score(findings)

    return {
        "score": score,
        "issues": findings
    }


#testing my changes