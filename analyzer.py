# analyzer.py
#
# Purpose:
# Runs srcML on a source file, parses the XML, extracts useful code
# structures such as function calls, and sends them to rules.py for
# security checks.
#
# Usage:
#   python analyzer.py samples/test.cpp
#
# Expected rules.py functions:
#   check_dangerous_calls(calls) -> list[dict]
#   calculate_score(findings) -> int

from __future__ import annotations

import os
import sys
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from rules import check_dangerous_calls, calculate_score


def run_srcml(file_path: str) -> str:
    """
    Convert a source file into srcML XML using the srcml command.

    REQUIRES:
        - file_path exists
        - srcml is installed and available on PATH

    ENSURES:
        - returns XML as a string
        - raises an exception if conversion fails
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Source file not found: {file_path}")

    if shutil.which("srcml") is None:
        raise RuntimeError(
            "srcML is not installed or not on PATH. "
            "Install srcML and make sure the 'srcml' command works in terminal."
        )

    try:
        result = subprocess.run(
            ["srcml", file_path],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else "Unknown srcML error."
        raise RuntimeError(f"srcML failed: {stderr}") from exc


def parse_xml(xml_text: str) -> ET.Element:
    """
    Parse XML text into an ElementTree root node.

    REQUIRES:
        - xml_text is valid XML

    ENSURES:
        - returns root XML element
    """
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise RuntimeError(f"Failed to parse srcML XML: {exc}") from exc


def strip_namespace(tag: str) -> str:
    """
    Remove XML namespace from a tag.

    Example:
        '{http://www.srcML.org/srcML/src}call' -> 'call'
    """
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def get_full_text(node: Optional[ET.Element]) -> str:
    """
    Collect all text from a node and its children.
    """
    if node is None:
        return ""
    return "".join(node.itertext()).strip()


def get_function_name(call_node: ET.Element) -> str:
    """
    Extract function name from a srcML <call> node.

    srcML usually stores function calls like:
        <call>
          <name>gets</name>
          <argument_list>(...)</argument_list>
        </call>

    This function attempts to recover the call name even if nested.
    """
    for child in call_node:
        if strip_namespace(child.tag) == "name":
            return get_full_text(child)
    return ""


def get_line_number(node: ET.Element) -> Optional[str]:
    """
    Try to recover line number information if present in srcML attributes.
    Different srcML builds/configurations may or may not include positions.
    """
    for key, value in node.attrib.items():
        lowered = key.lower()
        if "line" in lowered:
            return value
    return None


def extract_function_calls(root: ET.Element) -> List[Dict[str, Any]]:
    """
    Extract function calls from srcML XML.

    Returns a list like:
    [
        {
            "function": "gets",
            "text": "gets(buffer)",
            "line": "12"
        },
        ...
    ]
    """
    calls: List[Dict[str, Any]] = []

    for node in root.iter():
        if strip_namespace(node.tag) != "call":
            continue

        function_name = get_function_name(node)
        call_text = get_full_text(node)
        line_number = get_line_number(node)

        if function_name:
            calls.append({
                "function": function_name,
                "text": call_text,
                "line": line_number
            })

    return calls


def analyze_file(file_path: str) -> Dict[str, Any]:
    """
    Run the complete analysis pipeline on a source file.

    Steps:
        1. Convert source to srcML XML
        2. Parse XML
        3. Extract function calls
        4. Send calls to rules.py
        5. Calculate score
        6. Return structured results
    """
    xml_text = run_srcml(file_path)
    root = parse_xml(xml_text)
    calls = extract_function_calls(root)

    findings = check_dangerous_calls(calls)
    score = calculate_score(findings)

    return {
        "file": file_path,
        "score": score,
        "calls": calls,
        "findings": findings
    }


def print_results(results: Dict[str, Any]) -> None:
    """
    Pretty-print results for terminal testing.
    """
    print(f"\nAnalyzed File: {results['file']}")
    print(f"Security Score: {results['score']}")
    print("-" * 50)

    findings = results.get("findings", [])
    if not findings:
        print("No risky patterns detected.")
        return

    for index, finding in enumerate(findings, start=1):
        severity = finding.get("severity", "Unknown")
        issue = finding.get("issue", "No issue message provided.")
        explanation = finding.get("explanation", "No explanation provided.")
        function_name = finding.get("function", "Unknown")
        line_number = finding.get("line", "Unknown")

        print(f"{index}. [{severity}] {issue}")
        print(f"   Function: {function_name}")
        print(f"   Line: {line_number}")
        print(f"   Reason: {explanation}")
        print()


def main() -> None:
    """
    CLI entry point for quick backend testing.
    """
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <source-file>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        results = analyze_file(file_path)
        print_results(results)
    except Exception as exc:
        print(f"Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()