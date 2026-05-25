from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..text_extract import extract_docx_text
from ..utils import normalize_path


SEVERITY_HEADINGS = {
    "高等级缺陷": "high",
    "中等级缺陷": "medium",
    "低等级缺陷": "low",
}


def parse_code_guard_docx(path: Path, project: str = "") -> dict[str, Any]:
    text = extract_docx_text(path)
    lines = [line.strip() for line in text.splitlines()]
    findings = parse_code_guard_text(lines, path)
    return {
        "tool": "code_guard",
        "project": project,
        "source": str(path),
        "summary": parse_summary(lines),
        "findings_count": len(findings),
        "findings": findings,
        "raw_text_length": len(text),
    }


def parse_summary(lines: list[str]) -> dict[str, Any]:
    text = "\n".join(lines[:200])
    summary: dict[str, Any] = {"counts": {"high": 0, "medium": 0, "low": 0}}
    name_match = re.search(r"源代码名称：([^\n]+)", text)
    if name_match:
        summary["project_name"] = name_match.group(1).strip()
    for label, key in [("高危", "high"), ("中危", "medium"), ("低危", "low")]:
        match = re.search(rf"{label}\n([0-9,]+)", text)
        if match:
            summary["counts"][key] = int(match.group(1).replace(",", ""))
    return summary


def parse_code_guard_text(lines: list[str], path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    current_severity = "unknown"
    current_rule = "Unknown"
    current_primary = ""
    current_secondary = ""
    index = 0
    while index < len(lines):
        line = lines[index]
        for heading, severity in SEVERITY_HEADINGS.items():
            if heading in line:
                current_severity = severity
        rule_match = re.match(r"^\d+\.\d+\.\d+\s+(.+)$", line)
        if rule_match:
            current_rule = rule_match.group(1).strip()
        if line.startswith("一级分类："):
            current_primary = line.split("：", 1)[1].strip()
        if line.startswith("二级分类："):
            current_secondary = line.split("：", 1)[1].strip()
            if current_primary:
                current_rule = f"{current_primary}：{current_secondary}"
        if re.match(r"^缺陷\d+【", line):
            block = collect_defect_block(lines, index)
            finding = parse_defect_block(block, current_rule, current_severity, path)
            if finding:
                findings.append(finding)
            index += max(len(block), 1)
            continue
        index += 1
    return findings


def collect_defect_block(lines: list[str], start: int) -> list[str]:
    block = [lines[start]]
    for line in lines[start + 1 :]:
        if re.match(r"^缺陷\d+【", line) or re.match(r"^\d+\.\d+\.\d+\s+", line):
            break
        block.append(line)
    return block


def parse_defect_block(block: list[str], rule_type: str, severity: str, path: Path) -> dict[str, Any] | None:
    joined = "\n".join(block)
    match = re.search(r"爆发行:(.+?)\s+([0-9]+)\s*(?:\n|$)", joined)
    if not match:
        return None
    file_path = normalize_path(match.group(1).strip())
    line_number = int(match.group(2))
    defect_id = block[0].split("【", 1)[0]
    trace = ""
    for index, line in enumerate(block):
        if line == "跟踪路径1:" and index + 1 < len(block):
            trace = block[index + 1]
            break
    return {
        "tool": "code_guard",
        "rule_type": rule_type,
        "title": f"{rule_type} {defect_id}",
        "severity": severity,
        "file_path": file_path,
        "line_start": line_number,
        "line_end": line_number,
        "evidence": trace or f"爆发行: {file_path}:{line_number}",
        "source_report": str(path),
        "confidence": "high",
    }

