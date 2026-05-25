from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..text_extract import extract_pdf_text
from ..utils import normalize_path


def parse_fortify_pdf(path: Path, project: str = "") -> dict[str, Any]:
    text = extract_pdf_text(path)
    lines = [line.strip() for line in text.splitlines()]
    findings = parse_fortify_text(lines, path)
    return {
        "tool": "fortify",
        "project": project,
        "source": str(path),
        "summary": parse_summary(lines),
        "findings_count": len(findings),
        "findings": findings,
        "raw_text_length": len(text),
    }


def parse_summary(lines: list[str]) -> dict[str, Any]:
    head = "\n".join(lines[:300])
    summary: dict[str, Any] = {"counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
    project_match = re.search(r"Project Name:\s*\n?([^\n]+)", head)
    if project_match:
        summary["project_name"] = project_match.group(1).strip()
    for english, key in [("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low")]:
        match = re.search(rf"([0-9,]+)\s*\n?{english}\b", head)
        if match:
            summary["counts"][key] = int(match.group(1).replace(",", ""))
    return summary


def parse_fortify_text(lines: list[str], path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    current_category = ""
    current_severity = "unknown"
    seen: set[tuple[str, str, int, str]] = set()
    for index, line in enumerate(lines):
        heading = re.match(r"^(.+?)\s+\(([0-9,]+)\s+issues?\)$", line)
        if heading:
            current_category = heading.group(1).strip()
            continue
        if line in {"Critical", "High", "Medium", "Low"}:
            current_severity = line.lower()
        if index + 1 < len(lines) and lines[index + 1] in {"Critical", "High", "Medium", "Low"} and is_likely_category(line):
            current_category = line
        if not line.startswith("File: "):
            continue
        file_path, line_number = split_file_line(line[6:].strip())
        if not file_path or line_number is None:
            continue
        nearby_category = find_category_nearby(lines, index)
        category = nearby_category or current_category or "Unknown"
        if category in {"Structural", "Semantic", "Data Flow", "Control Flow", "Configuration", "Content", "...", "0"}:
            category = current_category or "Unknown"
        sink = find_prefixed_nearby(lines, index, "Sink:")
        source = find_prefixed_nearby(lines, index, "Source:")
        key = (category, normalize_path(file_path), line_number, sink or source or "")
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "tool": "fortify",
                "rule_type": category,
                "title": category,
                "severity": current_severity,
                "file_path": normalize_path(file_path),
                "line_start": line_number,
                "line_end": line_number,
                "sink": sink,
                "source": source,
                "evidence": " | ".join(item for item in [source, sink, f"File: {file_path}:{line_number}"] if item),
                "source_report": str(path),
                "confidence": "medium",
            }
        )
    return findings


def split_file_line(value: str) -> tuple[str | None, int | None]:
    if ":" not in value:
        return None, None
    file_path, line_number = value.rsplit(":", 1)
    try:
        return file_path.strip(), int(line_number.strip())
    except ValueError:
        return None, None


def find_category_nearby(lines: list[str], index: int) -> str | None:
    for offset in range(1, 12):
        candidate = lines[index - offset] if index - offset >= 0 else ""
        if candidate.startswith("Scan Engine:"):
            continue
        match = re.search(r"\(([^()]+)\)$", candidate)
        if match:
            return match.group(1).strip()
    return None


def find_prefixed_nearby(lines: list[str], index: int, prefix: str) -> str | None:
    for offset in range(1, 8):
        candidate = lines[index - offset] if index - offset >= 0 else ""
        if candidate.startswith(prefix):
            return candidate
    return None


def is_likely_category(line: str) -> bool:
    if not line or line.startswith(("File:", "Sink:", "Source:", "Scan Engine:", "Package:", "Kingdom:")):
        return False
    if "/" in line or line.startswith(("Apr ", "© ", "Taint Flags")):
        return False
    return bool(re.search(r"[A-Za-z]", line))
