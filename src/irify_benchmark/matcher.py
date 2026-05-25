from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import path_matches, read_yaml, write_json


def load_findings(path: Path) -> list[dict[str, Any]]:
    data = read_yaml(path) if path.suffix in {".yaml", ".yml"} else __import__("json").loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return data.get("findings", [])
    return data


def load_annotations(path: Path) -> list[dict[str, Any]]:
    data = read_yaml(path)
    if isinstance(data, dict):
        return data.get("annotations") or data.get("cases") or []
    return data or []


def match_annotations(annotations: list[dict[str, Any]], findings: list[dict[str, Any]], line_window: int = 3) -> dict[str, Any]:
    matched: list[dict[str, Any]] = []
    unmatched_annotations: list[dict[str, Any]] = []
    used_findings: set[int] = set()
    for annotation in annotations:
        best_index = None
        best_score = -1
        for index, finding in enumerate(findings):
            if index in used_findings:
                continue
            score = score_match(annotation, finding, line_window)
            if score > best_score:
                best_index = index
                best_score = score
        if best_index is not None and best_score >= 90:
            used_findings.add(best_index)
            matched.append(
                {
                    "case_id": annotation.get("case_id"),
                    "score": best_score,
                    "annotation": annotation,
                    "finding": findings[best_index],
                }
            )
        else:
            unmatched_annotations.append(annotation)
    unmatched_findings = [finding for index, finding in enumerate(findings) if index not in used_findings]
    return {
        "annotations": len(annotations),
        "findings": len(findings),
        "tp": len(matched),
        "fn": len(unmatched_annotations),
        "unreviewed_findings": len(unmatched_findings),
        "sample_recall": round(len(matched) / len(annotations), 4) if annotations else None,
        "matched": matched,
        "unmatched_annotations": unmatched_annotations,
        "unreviewed_findings_sample": unmatched_findings[:50],
        "note": "当前只基于样例人工标注集计算召回；未审计 finding 不直接等价于误报。",
    }


def score_match(annotation: dict[str, Any], finding: dict[str, Any], line_window: int) -> int:
    score = 0
    if path_matches(annotation.get("file_path", ""), finding.get("file_path", "")):
        score += 45
    try:
        if abs(int(annotation.get("line_start", 0)) - int(finding.get("line_start", 0))) <= line_window:
            score += 35
    except (TypeError, ValueError):
        pass
    if rule_matches(annotation, finding):
        score += 25
    return score


def rule_matches(annotation: dict[str, Any], finding: dict[str, Any]) -> bool:
    rule = str(finding.get("rule_type", "")).lower()
    candidates = [str(annotation.get("rule_type", ""))]
    candidates.extend(str(item) for item in annotation.get("aliases", []) or [])
    return any(candidate.lower() in rule or rule in candidate.lower() for candidate in candidates if candidate)


def write_match_report(path: Path, annotations_path: Path, findings_path: Path, line_window: int = 3) -> dict[str, Any]:
    result = match_annotations(load_annotations(annotations_path), load_findings(findings_path), line_window)
    write_json(path, result)
    return result
