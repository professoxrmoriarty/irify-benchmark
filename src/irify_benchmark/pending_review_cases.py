from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
from typing import Any

from .utils import ensure_dir, read_json, slugify, write_yaml


OWASP_FAMILY_MAP = {
    "A01 Broken Access Control": "broken_access_control",
    "A02 Cryptographic Failures": "cryptographic_failure",
    "A03 Injection": "injection",
    "A05 Security Misconfiguration": "security_misconfiguration",
    "A06 Vulnerable and Outdated Components": "vulnerable_component",
    "A07 Identification and Authentication Failures": "credential_management",
    "A08 Software and Data Integrity Failures": "software_data_integrity_failure",
    "A10 Server-Side Request Forgery": "ssrf",
}


def export_pending_review_cases(
    evaluation_path: Path,
    output_path: Path,
    tool: str = "irify",
) -> dict[str, Any]:
    evaluation = read_json(evaluation_path)
    pending = ((evaluation or {}).get("pending_review_additions", {}) or {}).get(tool, []) or []
    project = str((evaluation or {}).get("project") or "unknown")

    cases = []
    priority_counter = Counter()
    for index, item in enumerate(pending, start=1):
        priority = str(item.get("review_priority") or "medium")
        priority_counter[priority] += 1
        cases.append(build_review_case(project, tool, index, item))

    payload = {
        "project": project,
        "tool": tool,
        "generated_from": str(evaluation_path),
        "summary": {
            "total": len(cases),
            "by_priority": dict(priority_counter),
        },
        "notes": [
            "这是待复核 finding 转出的 review case 草案，不自动参与正式真值评估。",
            "人工确认后，可按需要提升到 JavaSecLab.review.yaml 的 manual_cases 或 suppressed_findings。",
            "candidate_case_ids 非空时，优先判断是否应并入已有 case，而不是直接新增。"
        ],
        "review_cases": cases,
    }
    ensure_dir(output_path.parent)
    write_yaml(output_path, payload)
    return payload


def build_review_case(project: str, tool: str, index: int, item: dict[str, Any]) -> dict[str, Any]:
    rule_name = str(item.get("rule_name") or "")
    file_path = str(item.get("file_path") or "")
    line_start = int(item.get("line_start", 0) or 0)
    owasp_category = str(item.get("owasp_category") or "")
    family = guess_family(rule_name, owasp_category)
    file_stem = Path(file_path).stem or "file"
    case_slug = slugify(f"{file_stem}-{line_start}-{rule_name}")[:72]
    case_id = f"PENDING-{tool.upper()}-{index:03d}"

    if item.get("candidate_case_ids"):
        proposed_action = "merge_or_expand_existing_case"
    else:
        proposed_action = "new_case_candidate"

    return {
        "review_case_id": case_id,
        "review_status": "pending_review",
        "proposed_action": proposed_action,
        "candidate_case_ids": list(item.get("candidate_case_ids") or []),
        "owasp_category": owasp_category,
        "review_priority": str(item.get("review_priority") or "medium"),
        "reason": str(item.get("reason") or ""),
        "finding": {
            "tool": tool,
            "rule_name": rule_name,
            "severity": str(item.get("severity") or ""),
            "file_path": file_path,
            "line_start": line_start,
            "evidence": str(item.get("evidence") or ""),
        },
        "proposed_case": {
            "case_id": f"REVIEW-{project.upper()}-{index:03d}",
            "scenario_id": f"pending.{slugify(project)}.{case_slug}",
            "family": family,
            "title": guess_title(rule_name, file_path),
            "description": f"待复核新增项：{rule_name} @ {file_path}:{line_start}",
            "expectation": "must_alert",
            "canonical_file_path": file_path,
            "line_start": line_start,
            "line_end": line_start,
            "rule_type": normalize_rule_type(rule_name),
            "aliases": [rule_name],
            "source_notes": str(item.get("evidence") or ""),
            "sink_api": rule_name,
            "source_refs": [f"{file_path}:{line_start}"],
            "notes": [
                "由 pending_review_additions 自动导出。",
                "人工确认后再移动到正式 manual_cases。"
            ],
        },
    }


def guess_family(rule_name: str, owasp_category: str) -> str:
    rule_lower = rule_name.lower()
    patterns = [
        (r"sql", "sql_injection"),
        (r"command", "command_injection"),
        (r"path traversal|path manipulation|路径穿越|路径遍历", "path_traversal"),
        (r"\bxss\b|跨站脚本", "xss"),
        (r"xxe|xml external entity|xmlreader|xmldecoder", "xxe"),
        (r"ssti|template injection", "ssti"),
        (r"deserial|反序列化|xstream|snakeyaml|fastjson", "deserialization"),
        (r"credential|password|凭据|硬编码", "credential_management"),
        (r"ssrf|服务端请求伪造", "ssrf"),
    ]
    for pattern, family in patterns:
        if re.search(pattern, rule_lower, re.IGNORECASE):
            return family
    return OWASP_FAMILY_MAP.get(owasp_category, "pending_review")


def guess_title(rule_name: str, file_path: str) -> str:
    file_name = Path(file_path).name or "unknown"
    if rule_name:
        return f"{rule_name} @ {file_name}"
    return file_name


def normalize_rule_type(rule_name: str) -> str:
    if not rule_name:
        return "Pending Review"
    return rule_name
