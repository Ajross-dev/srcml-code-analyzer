from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from rules import calculate_score, check_code_smells, check_dangerous_calls


def run_srcml(file_path: str) -> str:
    """
    Run srcML on a C++ source file and return XML output.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Source file not found: {file_path}")

    if shutil.which("srcml") is None:
        raise RuntimeError(
            "srcML is not installed or not on PATH. "
            "Install srcML and make sure the 'srcml' command works."
        )

    try:
        result = subprocess.run(
            ["srcml", "--language", "C++", file_path],
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
    Parse srcML XML text into an ElementTree root.
    """
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise RuntimeError(f"Failed to parse srcML XML: {exc}") from exc


def strip_namespace(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def get_full_text(node: Optional[ET.Element]) -> str:
    if node is None:
        return ""
    return "".join(node.itertext()).strip()


def get_line_number(node: ET.Element) -> Optional[str]:
    """
    Try to recover line number information if present.
    """
    for key, value in node.attrib.items():
        lower_key = key.lower()
        if "line" in lower_key:
            return value
    return None


def get_call_name(call_node: ET.Element) -> str:
    """
    Extract the function name from a srcML <call> node.
    """
    for child in call_node:
        if strip_namespace(child.tag) == "name":
            return get_full_text(child)
    return ""


def extract_function_calls(root: ET.Element) -> List[Dict[str, Any]]:
    calls: List[Dict[str, Any]] = []

    for node in root.iter():
        if strip_namespace(node.tag) != "call":
            continue

        function_name = get_call_name(node)
        call_text = get_full_text(node)
        line_number = get_line_number(node)

        if function_name:
            calls.append({
                "function": function_name,
                "text": call_text,
                "line": line_number
            })

    return calls


def extract_functions(root: ET.Element) -> List[Dict[str, Any]]:
    """
    Extract function definitions for code smell checks.
    """
    functions: List[Dict[str, Any]] = []

    for node in root.iter():
        if strip_namespace(node.tag) != "function":
            continue

        function_name = "unknown"
        line_number = get_line_number(node)
        text = get_full_text(node)

        for child in node:
            if strip_namespace(child.tag) == "name":
                function_name = get_full_text(child)
                break

        functions.append({
            "name": function_name,
            "text": text,
            "line": line_number,
            "length_estimate": len(text.splitlines()) if text else 0
        })

    return functions


def analyze_file(file_path: str) -> Dict[str, Any]:
    xml_text = run_srcml(file_path)
    root = parse_xml(xml_text)

    calls = extract_function_calls(root)
    functions = extract_functions(root)

    findings: List[Dict[str, Any]] = []
    findings.extend(check_dangerous_calls(calls))
    findings.extend(check_code_smells(functions, calls))

    score = calculate_score(findings)

    return {
        "file": file_path,
        "calls": calls,
        "functions": functions,
        "findings": findings,
        "score": score
    }


def analyze_code_text(code: str) -> Dict[str, Any]:
    """
    Analyze pasted C++ code by writing it to a temporary .cpp file.
    """
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".cpp",
            delete=False,
            encoding="utf-8"
        ) as temp_file:
            temp_file.write(code)
            temp_path = temp_file.name

        return analyze_file(temp_path)

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <cpp-file>")
        raise SystemExit(1)

    result = analyze_file(sys.argv[1])
    print(json.dumps(result, indent=2))