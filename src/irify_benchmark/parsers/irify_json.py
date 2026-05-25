from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "middle": "medium",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def parse_irify_json(path: Path, project: str = "") -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for risk in raw.get("Risks", {}).values():
        findings.append(
            {
                "tool": "irify",
                "rule_type": risk.get("rule_name") or risk.get("title") or "Unknown",
                "title": risk.get("title") or risk.get("title_verbose") or risk.get("rule_name") or "Unknown",
                "severity": SEVERITY_MAP.get(str(risk.get("severity")).lower(), str(risk.get("severity")).lower()),
                "file_path": normalize_irify_path(risk.get("code_source_url", "")),
                "line_start": int(risk.get("line") or 0) or 1,
                "line_end": int(risk.get("line") or 0) or 1,
                "source": None,
                "sink": None,
                "evidence": build_evidence(risk),
                "source_report": str(path),
                "confidence": "medium",
                "risk_feature_hash": risk.get("risk_feature_hash"),
            }
        )
    summary = {
        "project_name": raw.get("program_name"),
        "engine_version": raw.get("engine_version"),
        "report_time": raw.get("report_time"),
        "risk_count": raw.get("RiskNums", len(findings)),
        "file_count": raw.get("file_count"),
        "code_line_count": raw.get("code_line_count"),
        "scan_start_time": raw.get("scan_start_time"),
        "scan_end_time": raw.get("scan_end_time"),
        "counts": count_by_severity(findings),
    }
    return {
        "tool": "irify",
        "project": project or raw.get("program_name", ""),
        "source": str(path),
        "summary": summary,
        "findings_count": len(findings),
        "findings": findings,
        "raw_rule_count": len(raw.get("Rules", [])),
    }


def normalize_irify_path(path: str) -> str:
    value = str(path or "").replace("\\", "/")
    value = re.sub(r"^/[^/]+/\s*", "", value)
    value = re.sub(r"^/[^/]+", "", value)
    return value.lstrip("/")


def build_evidence(risk: dict[str, Any]) -> str:
    parts = []
    if risk.get("rule_name"):
        parts.append(str(risk["rule_name"]))
    if risk.get("title_verbose"):
        parts.append(str(risk["title_verbose"]))
    if risk.get("details"):
        details = str(risk["details"]).strip().replace("\n", " ")
        parts.append(details[:300])
    return " | ".join(part for part in parts if part)


def count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity")
        if severity in counts:
            counts[severity] += 1
    return counts
