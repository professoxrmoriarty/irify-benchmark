from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
from typing import Any

from .rule_index import index_java_rules
from .scenario_discovery import discover_java_scenarios
from .truth_profiles import get_family_profile
from .utils import normalize_path, path_matches, read_yaml, write_json, write_yaml


TOOL_PRIORITY = ["irify", "code_guard", "fortify"]

PENDING_REVIEW_POLICY_VERSION = "owasp_top10_high_signal_v1"
PENDING_REVIEW_POLICY_DESCRIPTION = (
    "只保留 OWASP Top10 且具备新增案例价值的高信号 finding，"
    "过滤注释/调试/资源释放/泛型异常等低价值噪声、第三方静态资产，"
    "并折叠同规则同 scope 的重复告警。"
)
PENDING_REVIEW_COMMENT_RULE_PATTERNS = (
    r"注释",
    r"comment",
    r"邮箱地址",
    r"url地址",
)
PENDING_REVIEW_NOISE_RULE_PATTERNS = (
    r"泛型异常捕获",
    r"overly broad catch",
    r"overly broad throws",
    r"泛化的捕获异常",
    r"泛化的抛出异常",
    r"空.?catch",
    r"empty catch",
    r"资源未释放",
    r"unreleased resource",
    r"未检查返回值",
    r"unchecked return",
    r"系统信息泄露",
    r"system information leak",
    r"printstacktrace",
    r"system output stream",
    r"system\.out",
    r"日志伪造",
    r"poor logging",
    r"侵犯隐私",
    r"privacy violation",
    r"肩窥",
    r"遗留的调试代码",
    r"leftover debug",
    r"target blank",
    r"alt属性",
    r"img中缺少alt属性",
    r"过时的属性",
    r"过时的标签",
    r"数据库访问控制",
    r"getconnection\(\)",
    r"直接管理数据库连接",
    r"线程规则",
    r"value never read",
    r"byte array to string",
    r"e2e-ssa-irdb-incremental-rule",
    r"^unknown$",
    r"insecure randomness",
    r"拒绝服务[:：]?\s*stringbuilder",
    r"denial of service",
    r"CSRF",
    r"cross-site request forgery",
)
PENDING_REVIEW_THIRD_PARTY_PATH_PATTERNS = (
    r"/static/lib/",
    r"/third-party/",
    r"jquery",
    r"layui",
    r"webuploader",
    r"ueditor",
)
PENDING_REVIEW_OWASP_CATEGORY_PATTERNS: dict[str, tuple[str, ...]] = {
    "A01 Broken Access Control": (
        r"idor",
        r"越权",
        r"access control",
        r"路径遍历",
        r"路径穿越",
        r"path traversal",
        r"path manipulation",
        r"访问权限修饰符修改",
    ),
    "A02 Cryptographic Failures": (
        r"cryptographic",
        r"加密",
        r"weak hash",
        r"encryption key",
        r"硬编码加密密钥",
    ),
    "A03 Injection": (
        r"sql注入",
        r"sql injection",
        r"mybatis",
        r"命令注入",
        r"command injection",
        r"\bxss\b",
        r"XSS",
        r"xpath",
        r"spel",
        r"ssti",
        r"template injection",
        r"http响应截断",
        r"crlf",
    ),
    "A05 Security Misconfiguration": (
        r"\bcors\b",
        r"跨域",
        r"xxe",
        r"xml external entity",
        r"xml entity expansion",
        r"missing xml validation",
        r"缺少xml验证",
    ),
    "A06 Vulnerable and Outdated Components": (
        r"^sca",
        r"易受攻击的框架",
        r"vulnerab",
        r"devtools",
        r"fastjson依赖",
        r"commons-collections",
        r"shiro-core",
        r"jackson-core",
        r"不安全的反序列化组件",
    ),
    "A07 Identification and Authentication Failures": (
        r"password",
        r"凭据",
        r"credential",
        r"硬编码密码",
        r"弱密码",
        r"empty password",
        r"页面密码明文输入",
        r"明文密码",
    ),
    "A08 Software and Data Integrity Failures": (
        r"反序列化",
        r"deserial",
        r"unserial",
        r"xmldecoder",
        r"fastjson",
        r"snakeyaml",
        r"xstream",
        r"access specifier manipulation",
        r"setaccessible",
    ),
    "A10 Server-Side Request Forgery": (
        r"ssrf",
        r"SSRF",
    ),
}
PENDING_REVIEW_PRIORITY_RANK = {"high": 2, "medium": 1}


def build_java_truth(
    project_name: str,
    source_root: Path,
    readme_path: Path,
    rules_root: Path,
    irify_findings_path: Path,
    code_guard_findings_path: Path | None,
    fortify_findings_path: Path | None,
    review_config_path: Path | None = None,
) -> dict[str, Any]:
    scenarios_doc = discover_java_scenarios(source_root, readme_path)
    rule_index = index_java_rules(rules_root)
    review_config = load_review_config(review_config_path)
    findings = {
        "irify": load_findings(irify_findings_path),
        "code_guard": load_findings(code_guard_findings_path) if code_guard_findings_path else [],
        "fortify": load_findings(fortify_findings_path) if fortify_findings_path else [],
    }
    cases = []
    for raw_case in scenarios_doc["scenarios"]:
        case = dict(raw_case)
        del case["body_lines"]
        profile = get_family_profile(case["family"])
        candidates = select_rule_candidates(rule_index["rules"], profile["rule_selectors"])
        case["irify_rule_candidates"] = candidates
        case["aliases"] = unique_strings(case["aliases"] + [rule["title_zh"] for rule in candidates if rule["title_zh"]] + [rule["title"] for rule in candidates if rule["title"]])
        apply_case_override(case, review_config)
        sink = detect_sink(raw_case, findings, profile)
        case["sink"] = sink
        case["trace"] = build_trace(case, sink)
        case["scan_observed_rules"] = {
            tool: observed_matches(raw_case, findings[tool], case["aliases"], profile["supported"]) for tool in TOOL_PRIORITY
        }
        case["verification_status"] = {
            tool: evaluate_case(case["expectation"], case.get("expected_severity_band", []), case["scan_observed_rules"][tool], profile["supported"])
            for tool in TOOL_PRIORITY
        }
        case["notes"] = build_case_notes(case)
        cases.append(case)
    for manual_case in review_config.get("manual_cases", []):
        case = normalize_manual_case(manual_case)
        apply_case_override(case, review_config)
        case["scan_observed_rules"] = {
            tool: observed_matches(case, findings[tool], case["aliases"], case.get("irify_support") == "supported")
            for tool in TOOL_PRIORITY
        }
        case["verification_status"] = {
            tool: evaluate_case(
                case["expectation"],
                case.get("expected_severity_band", []),
                case["scan_observed_rules"][tool],
                case.get("irify_support") == "supported",
            )
            for tool in TOOL_PRIORITY
        }
        if not case.get("sink"):
            case["sink"] = detect_manual_sink(case)
        if not case.get("trace"):
            case["trace"] = build_manual_trace(case)
        cases.append(case)
    truth = {
        "project": project_name,
        "source": "java_truth_builder_v3",
        "notes": [
            f"以 {project_name} 靶场/项目源码里的 vul/safe 或可识别场景为真值主口径。",
            "IRify 内置规则来源于 sfbuildin Java 规则目录。",
            "镜像/副本源码路径不单独计数，统一折叠到 canonical file path。",
        ],
        "metadata": {
            "summary": scenarios_doc["summary"],
            "rule_count": rule_index["rule_count"],
            "rules_root": str(rules_root),
            "source_root": str(source_root),
            "readme_path": str(readme_path),
            "review_config_path": str(review_config_path) if review_config_path and review_config_path.exists() else "",
        },
        "cases": cases,
    }
    pending_review_additions, pending_review_policy = build_pending_review_additions(cases, findings, review_config)
    truth["pending_review_additions"] = pending_review_additions
    truth["pending_review_policy"] = pending_review_policy
    return truth




def build_manual_truth(
    project_name: str,
    review_config_path: Path,
    irify_findings_path: Path,
    code_guard_findings_path: Path | None = None,
    fortify_findings_path: Path | None = None,
    source_root: Path | None = None,
    language: str = "",
) -> dict[str, Any]:
    review_config = load_review_config(review_config_path)
    findings = {
        "irify": load_findings(irify_findings_path),
        "code_guard": load_findings(code_guard_findings_path) if code_guard_findings_path else [],
        "fortify": load_findings(fortify_findings_path) if fortify_findings_path else [],
    }
    cases = []
    for raw_manual_case in review_config.get("manual_cases", []) or []:
        case = normalize_manual_case(raw_manual_case)
        apply_case_override(case, review_config)
        case["scan_observed_rules"] = {
            tool: observed_matches(case, findings[tool], case["aliases"], case.get("irify_support") == "supported")
            for tool in TOOL_PRIORITY
        }
        case["verification_status"] = {
            tool: evaluate_case(
                case["expectation"],
                case.get("expected_severity_band", []),
                case["scan_observed_rules"][tool],
                case.get("irify_support") == "supported",
            )
            for tool in TOOL_PRIORITY
        }
        if not case.get("sink"):
            case["sink"] = detect_manual_sink(case)
        if not case.get("trace"):
            case["trace"] = build_manual_trace(case)
        case["notes"] = build_case_notes(case) + list(case.get("notes", []))
        cases.append(case)

    summary = {
        "total_cases": len(cases),
        "positive_cases": sum(1 for item in cases if item.get("expectation") == "must_alert"),
        "warn_cases": sum(1 for item in cases if item.get("expectation") == "should_warn"),
        "negative_cases": sum(1 for item in cases if item.get("expectation") == "must_not_alert"),
        "supported_cases": sum(1 for item in cases if item.get("irify_support") == "supported"),
    }
    truth = {
        "project": project_name,
        "source": "manual_truth_builder_v1",
        "notes": [
            f"以 {project_name} 的人工维护 manual_cases 作为当前真值口径。",
            "适用于 PHP / Go 等尚未接入自动场景发现器的样本。",
            "manual_cases 可逐步扩展，pending_review_additions 用于承接后续补标与清洗。",
        ],
        "metadata": {
            "summary": summary,
            "language": language,
            "source_root": str(source_root) if source_root else "",
            "review_config_path": str(review_config_path),
        },
        "cases": cases,
    }
    pending_review_additions, pending_review_policy = build_pending_review_additions(cases, findings, review_config)
    truth["pending_review_additions"] = pending_review_additions
    truth["pending_review_policy"] = pending_review_policy
    return truth
def build_javaseclab_truth(
    source_root: Path,
    readme_path: Path,
    rules_root: Path,
    irify_findings_path: Path,
    code_guard_findings_path: Path,
    fortify_findings_path: Path,
) -> dict[str, Any]:
    return build_java_truth(
        project_name="JavaSecLab",
        source_root=source_root,
        readme_path=readme_path,
        rules_root=rules_root,
        irify_findings_path=irify_findings_path,
        code_guard_findings_path=code_guard_findings_path,
        fortify_findings_path=fortify_findings_path,
        review_config_path=Path(__file__).resolve().parents[2] / "annotations" / "JavaSecLab.review.yaml",
    )


def load_findings(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return data.get("findings", [])
    return data


def select_rule_candidates(rules: list[dict[str, Any]], selectors: list[str]) -> list[dict[str, Any]]:
    if not selectors:
        return []
    selected = []
    for rule in rules:
        search_text = rule["search_text"]
        if any(selector.lower() in search_text for selector in selectors):
            selected.append(
                {
                    "rule_file": rule["relative_path"],
                    "rule_id": rule["rule_id"],
                    "title_zh": rule["title_zh"],
                    "title": rule["title"],
                    "risk": rule["risk"],
                }
            )
    return selected


def observed_matches(raw_case: dict[str, Any], findings: list[dict[str, Any]], aliases: list[str], supported: bool) -> list[dict[str, Any]]:
    if not supported:
        return []
    matches = []
    for finding in findings:
        if not path_matches(raw_case["canonical_file_path"], finding.get("file_path", "")):
            continue
        line = int(finding.get("line_start", 0) or 0)
        if line and raw_case["line_start"] <= line <= raw_case["line_end"]:
            if rule_matches(aliases, str(finding.get("rule_type", ""))):
                matches.append(
                    {
                        "rule_name": finding.get("rule_type"),
                        "severity": finding.get("severity"),
                        "line_start": line,
                        "evidence": finding.get("evidence", "")[:300],
                    }
                )
    return deduplicate_matches(matches)


def rule_matches(aliases: list[str], rule_name: str) -> bool:
    rule = rule_name.lower()
    return any(alias and (alias.lower() in rule or rule in alias.lower()) for alias in aliases)


def detect_sink(raw_case: dict[str, Any], findings: dict[str, list[dict[str, Any]]], profile: dict[str, Any]) -> dict[str, Any] | None:
    for tool in TOOL_PRIORITY:
        observed = observed_matches(raw_case, findings[tool], raw_case["aliases"], profile["supported"])
        if observed:
            best = sorted(observed, key=lambda item: (severity_rank(item.get("severity")), -item.get("line_start", 0)), reverse=True)[0]
            return {
                "kind": "observed_finding",
                "file_path": raw_case["canonical_file_path"],
                "line_start": best["line_start"],
                "line_end": best["line_start"],
                "api": best["rule_name"],
                "source_tool": tool,
                "evidence": best["evidence"],
            }
    for line in raw_case["body_lines"]:
        code = line["code"]
        if any(pattern in code for pattern in profile["sink_patterns"]):
            return {
                "kind": "heuristic_sink",
                "file_path": raw_case["canonical_file_path"],
                "line_start": line["line"],
                "line_end": line["line"],
                "api": code.strip(),
                "source_tool": "heuristic",
                "evidence": code.strip(),
            }
    return None


def build_trace(case: dict[str, Any], sink: dict[str, Any] | None) -> list[dict[str, Any]]:
    trace = [
        {
            "stage": "source",
            "file_path": case["canonical_file_path"],
            "line_start": case["source"]["line_start"],
            "line_end": case["source"]["line_end"],
            "symbol": ", ".join(item["name"] for item in case["source"]["params"]) or "unknown",
            "note": case["source"]["notes"],
        }
    ]
    if sink:
        trace.append(
            {
                "stage": "sink",
                "file_path": sink["file_path"],
                "line_start": sink["line_start"],
                "line_end": sink["line_end"],
                "symbol": sink.get("api"),
                "note": sink.get("evidence", ""),
            }
        )
    for guard in case.get("safe_guards", []):
        trace.append(
            {
                "stage": "guard",
                "file_path": case["canonical_file_path"],
                "line_start": guard["line"],
                "line_end": guard["line"],
                "symbol": guard["type"],
                "note": guard["description"],
            }
        )
    return trace


def evaluate_case(expectation: str, expected_band: list[str], observed: list[dict[str, Any]], supported: bool) -> str:
    if not supported:
        return "uncovered_by_rule"
    severities = {normalize_severity(item.get("severity")) for item in observed}
    if expectation == "must_alert":
        if not observed:
            return "covered_missed"
        if any(level in severities for level in expected_band):
            return "hit_exact"
        if any(level in severities for level in {"low", "medium"}):
            return "hit_downgraded"
        return "hit_unknown"
    if expectation == "should_warn":
        if not observed:
            return "warning_missed"
        if any(level in severities for level in expected_band or ["low", "medium"]):
            return "warning_matched"
        if any(level in severities for level in {"high", "critical"}):
            return "warning_overstated"
        return "warning_matched"
    if not observed:
        return "correct_negative"
    if any(level in severities for level in {"high", "critical"}):
        return "severe_false_positive"
    return "advisory_noise"


def build_case_notes(case: dict[str, Any]) -> list[str]:
    notes = []
    if case["expectation"] == "must_not_alert" and case.get("safe_guards"):
        notes.append("safe 场景存在显式防护逻辑，应作为负例集。")
    if not case["irify_rule_candidates"]:
        notes.append("当前未找到可直接映射的 Java 内置规则。")
    if case["scan_observed_rules"]["irify"] and case["expectation"] == "must_not_alert":
        notes.append("IRify 在 safe 场景出现命中，需重点复核误报。")
    if not case["scan_observed_rules"]["irify"] and case["expectation"] == "must_alert" and case["irify_rule_candidates"]:
        notes.append("存在规则映射但未命中，属于漏报候选。")
    return notes


def build_pending_review_additions(
    cases: list[dict[str, Any]],
    findings_by_tool: dict[str, list[dict[str, Any]]],
    review_config: dict[str, Any],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    result: dict[str, list[dict[str, Any]]] = {}
    policy = {
        "version": PENDING_REVIEW_POLICY_VERSION,
        "description": PENDING_REVIEW_POLICY_DESCRIPTION,
        "tools": {},
    }
    for tool, findings in findings_by_tool.items():
        extras: dict[tuple[Any, ...], dict[str, Any]] = {}
        stats = Counter()
        raw_total = 0
        raw_high_total = 0
        for finding in findings:
            matched_cases = matched_case_ids(cases, finding)
            if matched_cases:
                continue
            raw_total += 1
            if normalize_severity(finding.get("severity")) in {"high", "critical"}:
                raw_high_total += 1
            suppression_reason = match_suppressed_finding(tool, finding, review_config)
            if suppression_reason:
                stats[f"reviewed_out::{suppression_reason}"] += 1
                continue
            candidates = candidate_case_ids(cases, finding)
            decision = classify_pending_review_finding(finding, candidates)
            if not decision["keep"]:
                stats[decision["exclude_reason"]] += 1
                continue
            item = {
                "tool": tool,
                "rule_name": finding.get("rule_type"),
                "severity": finding.get("severity"),
                "file_path": finding.get("file_path"),
                "line_start": finding.get("line_start"),
                "evidence": finding.get("evidence", "")[:300],
                "reason": "owasp_top10_missing_truth_case",
                "candidate_case_ids": candidates,
                "owasp_category": decision["owasp_category"],
                "review_priority": decision["review_priority"],
            }
            dedupe_key = build_pending_review_dedupe_key(item)
            current = extras.get(dedupe_key)
            if current is None:
                extras[dedupe_key] = item
                continue
            stats["deduplicated_same_rule_scope"] += 1
            if pending_item_rank(item) > pending_item_rank(current):
                extras[dedupe_key] = item
        items = sorted(extras.values(), key=pending_item_sort_key)
        kept_high_total = sum(1 for item in items if normalize_severity(item.get("severity")) in {"high", "critical"})
        result[tool] = items
        policy["tools"][tool] = {
            "raw_total": raw_total,
            "raw_high_total": raw_high_total,
            "kept_total": len(items),
            "kept_high_total": kept_high_total,
            "excluded_total": max(raw_total - len(items), 0),
            "excluded_high_total": max(raw_high_total - kept_high_total, 0),
            "excluded_reasons": dict(stats),
        }
    return result, policy


def classify_pending_review_finding(finding: dict[str, Any], candidate_case_ids: list[str]) -> dict[str, Any]:
    rule_name = str(finding.get("rule_type") or finding.get("rule_name") or "")
    rule_lower = rule_name.lower().strip()
    file_path = normalize_path(str(finding.get("file_path") or ""))
    severity = normalize_severity(finding.get("severity"))

    if regex_matches_any(rule_lower, PENDING_REVIEW_COMMENT_RULE_PATTERNS):
        return {"keep": False, "exclude_reason": "comment_rule"}
    if regex_matches_any(rule_lower, PENDING_REVIEW_NOISE_RULE_PATTERNS):
        return {"keep": False, "exclude_reason": "low_signal_rule"}
    if regex_matches_any(file_path.lower(), PENDING_REVIEW_THIRD_PARTY_PATH_PATTERNS):
        return {"keep": False, "exclude_reason": "third_party_asset"}

    owasp_category = classify_pending_review_owasp_category(rule_lower)
    if not owasp_category:
        return {"keep": False, "exclude_reason": "non_owasp_top10"}

    if (
        owasp_category == "A05 Security Misconfiguration"
        and severity in {"low", "info"}
        and not regex_matches_any(rule_lower, (r"xxe", r"xml external entity", r"xml entity expansion"))
    ):
        return {"keep": False, "exclude_reason": "low_urgency_misconfiguration"}
    if owasp_category == "A02 Cryptographic Failures" and severity in {"low", "medium", "info"}:
        return {"keep": False, "exclude_reason": "low_urgency_crypto"}
    if severity == "info" and owasp_category not in {
        "A06 Vulnerable and Outdated Components",
        "A07 Identification and Authentication Failures",
    }:
        return {"keep": False, "exclude_reason": "informational_only"}

    return {
        "keep": True,
        "owasp_category": owasp_category,
        "review_priority": classify_pending_review_priority(owasp_category, severity, candidate_case_ids, file_path),
    }


def classify_pending_review_owasp_category(rule_lower: str) -> str:
    for category, patterns in PENDING_REVIEW_OWASP_CATEGORY_PATTERNS.items():
        if regex_matches_any(rule_lower, patterns):
            return category
    return ""


def classify_pending_review_priority(
    owasp_category: str,
    severity: str,
    candidate_case_ids: list[str],
    file_path: str,
) -> str:
    strong_categories = {
        "A01 Broken Access Control",
        "A03 Injection",
        "A06 Vulnerable and Outdated Components",
        "A07 Identification and Authentication Failures",
        "A08 Software and Data Integrity Failures",
        "A10 Server-Side Request Forgery",
    }
    if severity in {"critical", "high"}:
        return "high"
    if candidate_case_ids:
        return "high"
    if owasp_category in strong_categories and file_path.endswith((".java", ".xml", ".yml", ".yaml", ".properties", ".html")):
        return "high"
    return "medium"


def build_pending_review_dedupe_key(item: dict[str, Any]) -> tuple[Any, ...]:
    candidate_case_ids = tuple(sorted(item.get("candidate_case_ids") or []))
    dedupe_scope = candidate_case_ids if candidate_case_ids else "__no_candidate__"
    return (
        item.get("tool"),
        item.get("rule_name"),
        item.get("file_path"),
        dedupe_scope,
    )


def pending_item_rank(item: dict[str, Any]) -> tuple[int, int, int, int]:
    line_start = int(item.get("line_start", 0) or 0)
    return (
        PENDING_REVIEW_PRIORITY_RANK.get(str(item.get("review_priority") or "medium"), 0),
        1 if item.get("candidate_case_ids") else 0,
        severity_rank(item.get("severity")),
        -line_start,
    )


def pending_item_sort_key(item: dict[str, Any]) -> tuple[int, int, str, str, str, int]:
    line_start = int(item.get("line_start", 0) or 0)
    return (
        -PENDING_REVIEW_PRIORITY_RANK.get(str(item.get("review_priority") or "medium"), 0),
        -severity_rank(item.get("severity")),
        str(item.get("owasp_category") or ""),
        str(item.get("rule_name") or ""),
        str(item.get("file_path") or ""),
        line_start,
    )


def regex_matches_any(text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def load_review_config(review_config_path: Path | None) -> dict[str, Any]:
    if not review_config_path or not review_config_path.exists():
        return {}
    data = read_yaml(review_config_path) or {}
    if not isinstance(data, dict):
        return {}
    data.setdefault("case_overrides", {})
    data.setdefault("manual_cases", [])
    data.setdefault("suppressed_findings", [])
    return data


def apply_case_override(case: dict[str, Any], review_config: dict[str, Any]) -> None:
    override = (review_config.get("case_overrides", {}) or {}).get(case.get("case_id"), {})
    if not override:
        return
    if override.get("expectation") is not None:
        case["expectation"] = str(override["expectation"])
    if override.get("expected_severity_band") is not None:
        case["expected_severity_band"] = list(override.get("expected_severity_band") or [])
    if override.get("sanitizer_expectation") is not None:
        case["sanitizer_expectation"] = str(override["sanitizer_expectation"])
    if override.get("title") is not None:
        case["title"] = str(override["title"])
    if override.get("description") is not None:
        case["description"] = str(override["description"])
    if override.get("family") is not None:
        case["family"] = str(override["family"])
    if override.get("rule_type") is not None:
        case["rule_type"] = str(override["rule_type"])
    if override.get("route") is not None:
        case["route"] = str(override["route"])
    if override.get("line_start") is not None:
        case["line_start"] = int(override["line_start"])
    if override.get("line_end") is not None:
        case["line_end"] = int(override["line_end"])
    if case.get("source") and override.get("line_start") is not None:
        case["source"]["line_start"] = int(override["line_start"])
    if case.get("source") and override.get("line_end") is not None:
        case["source"]["line_end"] = int(override["line_end"])
    if case.get("sink") and override.get("sink_line_start") is not None:
        case["sink"]["line_start"] = int(override["sink_line_start"])
    if case.get("sink") and override.get("sink_line_end") is not None:
        case["sink"]["line_end"] = int(override["sink_line_end"])
    if override.get("aliases_add"):
        case["aliases"] = unique_strings(list(case.get("aliases", [])) + list(override.get("aliases_add", [])))
    if override.get("notes_add"):
        case["notes"] = list(case.get("notes", [])) + list(override.get("notes_add", []))


def normalize_manual_case(raw: dict[str, Any]) -> dict[str, Any]:
    line_start = int(raw.get("line_start", 0) or 0)
    line_end = int(raw.get("line_end", line_start) or line_start)
    file_path = normalize_path(str(raw.get("canonical_file_path") or raw.get("file_path") or ""))
    description = str(raw.get("description") or raw.get("title") or "")
    source = raw.get("source") or {
        "kind": raw.get("source_kind", "manual_review"),
        "line_start": line_start,
        "line_end": line_end,
        "params": list(raw.get("source_params", [])),
        "notes": raw.get("source_notes") or description or "人工补充案例",
    }
    sink = raw.get("sink") or {
        "kind": raw.get("sink_kind", "manual_sink"),
        "file_path": file_path,
        "line_start": int(raw.get("sink_line_start", line_start) or line_start),
        "line_end": int(raw.get("sink_line_end", line_end) or line_end),
        "api": raw.get("sink_api") or raw.get("rule_type") or raw.get("title"),
        "source_tool": raw.get("sink_source_tool", "manual"),
        "evidence": raw.get("sink_evidence") or description,
    }
    case = {
        "case_id": raw["case_id"],
        "scenario_id": raw["scenario_id"],
        "family": raw.get("family", "manual"),
        "module": raw.get("module", "manual"),
        "controller_name": raw.get("controller_name", "ManualCase"),
        "class_tags": raw.get("class_tags", "人工补充案例"),
        "controller_path": raw.get("controller_path", file_path),
        "canonical_file_path": file_path,
        "class_route": raw.get("class_route", ""),
        "route": raw.get("route", file_path),
        "method_name": raw.get("method_name", raw["case_id"].lower()),
        "title": raw.get("title", raw["case_id"]),
        "description": description,
        "expectation": raw.get("expectation", "must_alert"),
        "expected_severity_band": list(raw.get("expected_severity_band", ["high", "critical"])),
        "sanitizer_expectation": raw.get("sanitizer_expectation", "manual_review"),
        "line_start": line_start,
        "line_end": line_end,
        "source": source,
        "sink": sink,
        "trace": list(raw.get("trace", [])),
        "safe_guards": list(raw.get("safe_guards", [])),
        "rule_type": raw.get("rule_type", raw.get("title", "")),
        "aliases": unique_strings(list(raw.get("aliases", [])) + [raw.get("rule_type", ""), raw.get("title", "")]),
        "irify_support": raw.get("irify_support", "supported"),
        "irify_rule_candidates": list(raw.get("irify_rule_candidates", [])),
        "scan_observed_rules": {"irify": [], "code_guard": [], "fortify": []},
        "verification_status": {},
        "alias_locations": list(raw.get("alias_locations", [])),
        "source_refs": list(raw.get("source_refs", [f"{file_path}:{line_start}"])),
        "notes": list(raw.get("notes", [])),
    }
    return case


def detect_manual_sink(case: dict[str, Any]) -> dict[str, Any] | None:
    for tool in TOOL_PRIORITY:
        observed = case.get("scan_observed_rules", {}).get(tool, []) or []
        if observed:
            best = sorted(observed, key=lambda item: (severity_rank(item.get("severity")), -item.get("line_start", 0)), reverse=True)[0]
            return {
                "kind": "observed_finding",
                "file_path": case["canonical_file_path"],
                "line_start": best["line_start"],
                "line_end": best["line_start"],
                "api": best["rule_name"],
                "source_tool": tool,
                "evidence": best.get("evidence", ""),
            }
    return None


def build_manual_trace(case: dict[str, Any]) -> list[dict[str, Any]]:
    trace = [
        {
            "stage": "source",
            "file_path": case["canonical_file_path"],
            "line_start": case["source"]["line_start"],
            "line_end": case["source"]["line_end"],
            "symbol": ", ".join(item.get("name", "") for item in case["source"].get("params", [])) or case["source"].get("kind", "manual_review"),
            "note": case["source"].get("notes", ""),
        }
    ]
    if case.get("sink"):
        trace.append(
            {
                "stage": "sink",
                "file_path": case["sink"]["file_path"],
                "line_start": case["sink"]["line_start"],
                "line_end": case["sink"]["line_end"],
                "symbol": case["sink"].get("api"),
                "note": case["sink"].get("evidence", ""),
            }
        )
    return trace


def match_suppressed_finding(tool: str, finding: dict[str, Any], review_config: dict[str, Any]) -> str:
    for item in review_config.get("suppressed_findings", []) or []:
        if finding_signature_matches(item, finding, tool):
            return str(item.get("reason") or "manual_review")
    return ""


def finding_signature_matches(signature: dict[str, Any], finding: dict[str, Any], tool: str) -> bool:
    if signature.get("tool") and str(signature.get("tool")) != str(tool):
        return False
    if signature.get("file_path") and normalize_path(str(signature.get("file_path") or "")) != normalize_path(str(finding.get("file_path") or "")):
        return False
    if signature.get("rule_name") and str(signature.get("rule_name") or "") != str(finding.get("rule_type") or finding.get("rule_name") or ""):
        return False
    if signature.get("line_start") is not None and int(signature.get("line_start", 0) or 0) != int(finding.get("line_start", 0) or 0):
        return False
    return True


def matched_case_ids(cases: list[dict[str, Any]], finding: dict[str, Any]) -> list[str]:
    matched = []
    for case in cases:
        if case_matches_finding(case, finding):
            matched.append(case["case_id"])
    return matched


def candidate_case_ids(cases: list[dict[str, Any]], finding: dict[str, Any]) -> list[str]:
    candidates = []
    line = int(finding.get("line_start", 0) or 0)
    for case in cases:
        if path_matches(case["canonical_file_path"], finding.get("file_path", "")) and case["line_start"] <= line <= case["line_end"]:
            candidates.append(case["case_id"])
    return candidates[:8]


def case_matches_finding(case: dict[str, Any], finding: dict[str, Any]) -> bool:
    if not path_matches(case["canonical_file_path"], finding.get("file_path", "")):
        return False
    line = int(finding.get("line_start", 0) or 0)
    if not line or not (case["line_start"] <= line <= case["line_end"]):
        return False
    return rule_matches(case.get("aliases", []), str(finding.get("rule_type", "")))


def deduplicate_matches(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for item in matches:
        key = (item["rule_name"], item["line_start"])
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def severity_rank(severity: str | None) -> int:
    mapping = {"critical": 5, "high": 4, "medium": 3, "middle": 3, "low": 2, "info": 1}
    return mapping.get(str(severity).lower(), 0)


def normalize_severity(severity: str | None) -> str:
    mapping = {"middle": "medium"}
    key = str(severity or "").lower()
    return mapping.get(key, key)


def unique_strings(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def export_truth(path: Path, data: dict[str, Any]) -> None:
    if path.suffix in {".yaml", ".yml"}:
        write_yaml(path, data)
    else:
        write_json(path, data)
