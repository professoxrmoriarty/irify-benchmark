from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import read_json, read_yaml, write_json


TOOL_ORDER = ["irify", "code_guard", "fortify"]


def export_frontend_dataset(truth_path: Path, evaluation_path: Path, output_path: Path) -> dict[str, Any]:
    truth = read_yaml(truth_path)
    evaluation = read_json(evaluation_path)
    cases = truth.get("cases", [])
    pending = evaluation.get("pending_review_additions", {})
    pending_policy = evaluation.get("pending_review_policy", {})
    dataset = {
        "project": truth.get("project"),
        "meta": truth.get("metadata", {}),
        "summary": build_summary(cases, evaluation, pending_policy),
        "tools": build_tools(evaluation),
        "families": build_families(evaluation),
        "cases": [simplify_case(case) for case in cases],
        "pendingReviewAdditions": build_pending_items(pending),
        "pendingReviewPolicy": simplify_pending_policy(pending_policy),
        "statusLegend": {
            "hit_exact": "命中正例",
            "hit_downgraded": "降级命中",
            "covered_missed": "漏报",
            "warning_matched": "命中降级提示",
            "warning_missed": "降级提示漏报",
            "warning_overstated": "等级过高",
            "correct_negative": "safe 未命中",
            "advisory_noise": "降级提示",
            "severe_false_positive": "严重误报",
            "uncovered_by_rule": "未纳入规则覆盖",
        },
    }
    write_json(output_path, dataset)
    return dataset


def build_summary(cases: list[dict[str, Any]], evaluation: dict[str, Any], pending_policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "totalCases": len(cases),
        "positiveCases": sum(1 for item in cases if item.get("expectation") == "must_alert"),
        "warnCases": sum(1 for item in cases if item.get("expectation") == "should_warn"),
        "negativeCases": sum(1 for item in cases if item.get("expectation") == "must_not_alert"),
        "supportedCases": sum(1 for item in cases if item.get("irify_support") == "supported"),
        "pendingReviewTotals": {tool: len(items) for tool, items in evaluation.get("pending_review_additions", {}).items()},
        "pendingReviewRawTotals": {
            tool: int((pending_policy.get("tools", {}).get(tool, {}) or {}).get("raw_total", len(items)))
            for tool, items in evaluation.get("pending_review_additions", {}).items()
        },
    }


def build_tools(evaluation: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    pending_policy = evaluation.get("pending_review_policy", {}) or {}
    for key in TOOL_ORDER:
        stat = evaluation["overall"][key]
        policy = (pending_policy.get("tools", {}) or {}).get(key, {}) or {}
        rows.append(
            {
                "key": key,
                "label": {"irify": "IRify", "code_guard": "代码卫士", "fortify": "Fortify"}[key],
                "pending_review_raw": int(policy.get("raw_total", stat.get("pending_review_additions", 0))),
                "pending_review_high_raw": int(policy.get("raw_high_total", 0)),
                "pending_review_high_kept": int(policy.get("kept_high_total", 0)),
                "pending_review_high_excluded": int(policy.get("excluded_high_total", 0)),
                "pending_review_excluded": int(policy.get("excluded_total", 0)),
                **stat,
            }
        )
    return rows


def build_families(evaluation: dict[str, Any]) -> list[dict[str, Any]]:
    families = []
    for item in evaluation.get("families", []):
        families.append(
            {
                "family": item["family"],
                "positiveCases": item["positive_cases"],
                "safeCases": item["safe_cases"],
                "tools": {tool: item.get(tool, {}) for tool in TOOL_ORDER},
            }
        )
    return families


def simplify_case(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "caseId": case["case_id"],
        "scenarioId": case["scenario_id"],
        "family": case["family"],
        "title": case["title"],
        "description": case.get("description", ""),
        "route": case["route"],
        "expectation": case["expectation"],
        "expectedSeverityBand": case.get("expected_severity_band", []),
        "filePath": case["canonical_file_path"],
        "lineStart": case["line_start"],
        "lineEnd": case["line_end"],
        "source": case.get("source"),
        "sink": case.get("sink"),
        "trace": case.get("trace", []),
        "safeGuards": case.get("safe_guards", []),
        "ruleType": case["rule_type"],
        "aliases": case.get("aliases", []),
        "irifySupport": case.get("irify_support"),
        "ruleCandidates": case.get("irify_rule_candidates", []),
        "verificationStatus": case.get("verification_status", {}),
        "observedRules": case.get("scan_observed_rules", {}),
        "notes": case.get("notes", []),
    }


def build_pending_items(pending: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for tool in TOOL_ORDER:
        for item in pending.get(tool, []):
            items.append(
                {
                    "tool": tool,
                    "toolLabel": {"irify": "IRify", "code_guard": "代码卫士", "fortify": "Fortify"}[tool],
                    "ruleName": item.get("rule_name"),
                    "severity": item.get("severity"),
                    "filePath": item.get("file_path"),
                    "lineStart": item.get("line_start"),
                    "candidateCaseIds": item.get("candidate_case_ids", []),
                    "evidence": item.get("evidence", ""),
                    "reason": item.get("reason"),
                    "owaspCategory": item.get("owasp_category", ""),
                    "reviewPriority": item.get("review_priority", "medium"),
                }
            )
    return items


def simplify_pending_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": policy.get("version", ""),
        "description": policy.get("description", ""),
        "tools": {
            tool: {
                "rawTotal": item.get("raw_total", 0),
                "rawHighTotal": item.get("raw_high_total", 0),
                "keptTotal": item.get("kept_total", 0),
                "keptHighTotal": item.get("kept_high_total", 0),
                "excludedTotal": item.get("excluded_total", 0),
                "excludedHighTotal": item.get("excluded_high_total", 0),
                "excludedReasons": item.get("excluded_reasons", {}),
            }
            for tool, item in (policy.get("tools", {}) or {}).items()
        },
    }
