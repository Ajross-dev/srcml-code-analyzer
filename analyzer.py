from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from rules import calculate_score, check_code_smells, check_dangerous_calls


def run_srcml(file_path: str) -> str:
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Source file not found: {file_path}")

    if shutil.which("srcml") is None:
        raise RuntimeError(
            "srcML is not installed or not on PATH. "
            "Install srcML and make sure the 'srcml' command works."
        )

    try:
        result = subprocess.run(
            ["srcml", "--language", "C++", "--position", file_path],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else "Unknown srcML error."
        raise RuntimeError(f"srcML failed: {stderr}") from exc


def parse_xml(xml_text: str) -> ET.Element:
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


def parse_line_value(value: str) -> Optional[int]:
    """
    Parse srcML position values like '12:5' or plain line-like strings.
    """
    if not value:
        return None

    match = re.match(r"(\d+)", value)
    if match:
        return int(match.group(1))

    return None


def get_start_line(node: ET.Element) -> Optional[int]:
    for key, value in node.attrib.items():
        key_lower = key.lower()
        if "start" in key_lower or "line" in key_lower:
            parsed = parse_line_value(str(value))
            if parsed is not None:
                return parsed
    return None


def get_end_line(node: ET.Element) -> Optional[int]:
    for key, value in node.attrib.items():
        key_lower = key.lower()
        if "end" in key_lower:
            parsed = parse_line_value(str(value))
            if parsed is not None:
                return parsed
    return None


def get_call_name(call_node: ET.Element) -> str:
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
        start_line = get_start_line(node)

        if function_name:
            calls.append({
                "function": function_name,
                "text": call_text,
                "line": start_line if start_line is not None else "Unknown"
            })

    return calls


def extract_functions(root: ET.Element) -> List[Dict[str, Any]]:
    functions: List[Dict[str, Any]] = []

    for node in root.iter():
        if strip_namespace(node.tag) != "function":
            continue

        function_name = "unknown"
        start_line = get_start_line(node)
        end_line = get_end_line(node)
        text = get_full_text(node)

        for child in node:
            if strip_namespace(child.tag) == "name":
                function_name = get_full_text(child)
                break

        length_estimate = 0
        if start_line is not None and end_line is not None and end_line >= start_line:
            length_estimate = end_line - start_line + 1

        functions.append({
            "name": function_name,
            "text": text,
            "line": start_line if start_line is not None else "Unknown",
            "start_line": start_line,
            "end_line": end_line,
            "length_estimate": length_estimate
        })

    return functions


def extract_variables(root: ET.Element) -> List[Dict[str, Any]]:
    """
    Extract basic variable declarations from srcML <decl> nodes.
    """
    variables: List[Dict[str, Any]] = []

    for node in root.iter():
        if strip_namespace(node.tag) != "decl":
            continue

        var_name = None

        for child in node:
            if strip_namespace(child.tag) == "name":
                var_name = get_full_text(child)
                break

        if not var_name:
            continue

        variables.append({
            "name": var_name,
            "line": get_start_line(node) or "Unknown"
        })

    return variables


def analyze_file(file_path: str, code_text: Optional[str] = None) -> Dict[str, Any]:
    xml_text = run_srcml(file_path)
    root = parse_xml(xml_text)

    if code_text is None:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            code_text = handle.read()

    calls = extract_function_calls(root)
    functions = extract_functions(root)
    variables = extract_variables(root)

    findings: List[Dict[str, Any]] = []
    findings.extend(check_dangerous_calls(calls))
    findings.extend(check_code_smells(functions, calls, variables, code_text, root))

    score = calculate_score(findings)

    return {
        "file": file_path,
        "calls": calls,
        "functions": functions,
        "variables": variables,
        "findings": findings,
        "score": score
    }


def analyze_code_text(code: str) -> Dict[str, Any]:
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

        return analyze_file(temp_path, code)

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