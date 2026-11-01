from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .utils import read_yaml, write_json


TOOL_KEYS = ["fortify", "code_guard", "irify"]
ALERT_STATUSES = {"hit_exact", "hit_downgraded", "warning_matched", "warning_overstated", "advisory_noise", "severe_false_positive", "hit_unknown"}
HIGH_SEVERITY = {"critical", "high", "Critical", "High"}


def evaluate_truth(path: Path) -> dict[str, Any]:
    truth = read_yaml(path)
    cases = truth.get("cases", [])
    pending = truth.get("pending_review_additions", {})
    pending_policy = truth.get("pending_review_policy", {})
    overall = {tool: summarize_tool(cases, tool, pending.get(tool, [])) for tool in TOOL_KEYS}
    families = build_family_summary(cases)
    return {
        "project": truth.get("project"),
        "case_count": len(cases),
        "overall": overall,
        "families": families,
        "pending_review_additions": pending,
        "pending_review_policy": pending_policy,
    }


def summarize_tool(cases: list[dict[str, Any]], tool: str, pending_review_additions: list[dict[str, Any]]) -> dict[str, Any]:
    positive_total = positive_supported = strict_tp = relaxed_tp = positive_fn = 0
    warn_total = warn_supported = warn_matched = warn_missed = warn_overstated = 0
    safe_total = safe_supported = severe_fp = advisory_noise = safe_tn = 0
    unsupported = 0
    finding_reviewed_total = 0
    finding_useful_alerts = 0
    finding_confirmed_false_positive = 0
    finding_advisory_noise = 0
    finding_overstated = 0
    finding_pending_manual = 0
    high_risk_reviewed_total = 0
    high_risk_true_alerts = 0
    high_risk_confirmed_false_positive = 0
    high_risk_overstated = 0
    high_risk_pending_manual = 0
    for case in cases:
        status = case.get("verification_status", {}).get(tool, "uncovered_by_rule")
        expectation = case.get("expectation")
        observed = case.get("scan_observed_rules", {}).get(tool, []) or []
        observed_count = alert_count(status, observed)
        observed_high_count = high_alert_count(status, observed)
        if expectation == "must_alert":
            positive_total += 1
            if status == "uncovered_by_rule":
                unsupported += 1
                continue
            positive_supported += 1
            if status == "hit_exact":
                strict_tp += 1
                relaxed_tp += 1
                finding_reviewed_total += observed_count
                finding_useful_alerts += observed_count
                high_risk_reviewed_total += observed_high_count
                high_risk_true_alerts += observed_high_count
            elif status == "hit_downgraded":
                relaxed_tp += 1
                finding_reviewed_total += observed_count
                finding_useful_alerts += observed_count
                high_risk_reviewed_total += observed_high_count
                high_risk_true_alerts += observed_high_count
            elif status == "hit_unknown":
                positive_fn += 1
                finding_pending_manual += observed_count
                high_risk_pending_manual += observed_high_count
            else:
                positive_fn += 1
        elif expectation == "should_warn":
            warn_total += 1
            if status == "uncovered_by_rule":
                unsupported += 1
                continue
            warn_supported += 1
            if status == "warning_matched":
                warn_matched += 1
                finding_reviewed_total += observed_count
                finding_useful_alerts += observed_count
                high_risk_reviewed_total += observed_high_count
                high_risk_true_alerts += observed_high_count
            elif status == "warning_overstated":
                warn_overstated += 1
                finding_reviewed_total += observed_count
                finding_overstated += observed_count
                high_risk_reviewed_total += observed_high_count
                high_risk_overstated += observed_high_count
            elif status == "hit_unknown":
                warn_missed += 1
                finding_pending_manual += observed_count
                high_risk_pending_manual += observed_high_count
            else:
                warn_missed += 1
        elif expectation == "must_not_alert":
            safe_total += 1
            if status == "uncovered_by_rule":
                unsupported += 1
                continue
            safe_supported += 1
            if status == "severe_false_positive":
                severe_fp += 1
                finding_reviewed_total += observed_count
                finding_confirmed_false_positive += observed_count
                high_risk_reviewed_total += observed_high_count
                high_risk_confirmed_false_positive += observed_high_count
            elif status == "advisory_noise":
                advisory_noise += 1
                finding_reviewed_total += observed_count
                finding_advisory_noise += observed_count
                high_risk_reviewed_total += observed_high_count
            elif status == "hit_unknown":
                safe_tn += 1
                finding_pending_manual += observed_count
                high_risk_pending_manual += observed_high_count
            else:
                safe_tn += 1
    pending_review_count = len(pending_review_additions)
    pending_review_high = sum(1 for item in pending_review_additions if is_high_severity(item.get("severity")))
    finding_pending_total = pending_review_count
    high_risk_pending_total = pending_review_high
    finding_total = finding_reviewed_total + finding_pending_total
    high_risk_total = high_risk_reviewed_total + high_risk_pending_total
    finding_noise_total = finding_confirmed_false_positive + finding_advisory_noise + finding_overstated
    return {
        "positive_total": positive_total,
        "positive_supported": positive_supported,
        "positive_tp": strict_tp,
        "positive_relaxed_tp": relaxed_tp,
        "positive_fn": positive_fn,
        "positive_recall": round(strict_tp / positive_supported, 4) if positive_supported else None,
        "positive_relaxed_recall": round(relaxed_tp / positive_supported, 4) if positive_supported else None,
        "warn_total": warn_total,
        "warn_supported": warn_supported,
        "warn_matched": warn_matched,
        "warn_missed": warn_missed,
        "warn_overstated": warn_overstated,
        "warn_match_rate": round(warn_matched / warn_supported, 4) if warn_supported else None,
        "safe_total": safe_total,
        "safe_supported": safe_supported,
        "safe_fp": severe_fp,
        "safe_severe_fp": severe_fp,
        "safe_advisory_noise": advisory_noise,
        "safe_tn": safe_tn,
        "safe_fp_rate": round(severe_fp / safe_supported, 4) if safe_supported else None,
        "safe_advisory_rate": round(advisory_noise / safe_supported, 4) if safe_supported else None,
        "unsupported_cases": unsupported,
        "pending_review_additions": pending_review_count,
        "finding_reviewed_total": finding_reviewed_total,
        "finding_useful_alerts": finding_useful_alerts,
        "finding_confirmed_false_positive": finding_confirmed_false_positive,
        "finding_advisory_noise": finding_advisory_noise,
        "finding_overstated": finding_overstated,
        "finding_pending_manual": finding_pending_manual,
        "finding_pending_review": finding_pending_total,
        "finding_total": finding_total,
        "finding_noise_total": finding_noise_total,
        "finding_confirmed_fp_rate": round(finding_confirmed_false_positive / finding_reviewed_total, 4) if finding_reviewed_total else None,
        "finding_noise_rate": round(finding_noise_total / finding_reviewed_total, 4) if finding_reviewed_total else None,
        "finding_pending_rate": round(finding_pending_total / finding_total, 4) if finding_total else None,
        "finding_audit_load": round(finding_total / finding_useful_alerts, 4) if finding_useful_alerts else None,
        "high_risk_reviewed_total": high_risk_reviewed_total,
        "high_risk_true_alerts": high_risk_true_alerts,
        "high_risk_confirmed_false_positive": high_risk_confirmed_false_positive,
        "high_risk_overstated": high_risk_overstated,
        "high_risk_pending_manual": high_risk_pending_manual,
        "high_risk_pending_review": high_risk_pending_total,
        "high_risk_total": high_risk_total,
        "high_risk_false_positive_rate": round(high_risk_confirmed_false_positive / high_risk_reviewed_total, 4) if high_risk_reviewed_total else None,
        "high_risk_overreport_rate": round((high_risk_confirmed_false_positive + high_risk_overstated) / high_risk_reviewed_total, 4) if high_risk_reviewed_total else None,
        "high_risk_pending_rate": round(high_risk_pending_total / high_risk_total, 4) if high_risk_total else None,
    }


def build_family_summary(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        buckets[case.get("family", "unknown")].append(case)
    rows = []
    for family, items in sorted(buckets.items()):
        row: dict[str, Any] = {
            "family": family,
            "case_count": len(items),
            "positive_cases": sum(1 for item in items if item.get("expectation") == "must_alert"),
            "safe_cases": sum(1 for item in items if item.get("expectation") == "must_not_alert"),
        }
        for tool in TOOL_KEYS:
            tool_counter = Counter(item.get("verification_status", {}).get(tool, "uncovered_by_rule") for item in items)
            row[tool] = dict(tool_counter)
        rows.append(row)
    return rows


def export_evaluation(path: Path, data: dict[str, Any]) -> None:
    write_json(path, data)


def alert_count(status: str, observed: list[dict[str, Any]]) -> int:
    if status not in ALERT_STATUSES:
        return 0
    return len(observed) if observed else 1


def high_alert_count(status: str, observed: list[dict[str, Any]]) -> int:
    if status not in ALERT_STATUSES:
        return 0
    if not observed:
        return 1 if status in {"severe_false_positive", "warning_overstated"} else 0
    return sum(1 for item in observed if is_high_severity(item.get("severity")))


def is_high_severity(value: Any) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in HIGH_SEVERITY
