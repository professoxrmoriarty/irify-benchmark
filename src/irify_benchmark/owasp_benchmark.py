from __future__ import annotations

import csv
import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

from .parsers import parse_irify_json
from .utils import ensure_dir, write_json


REPO_ROOT = Path(__file__).resolve().parents[3]
TEST_NAME_PATTERN = re.compile(r"(BenchmarkTest\d{5})", re.IGNORECASE)
VERSION_PATTERN = re.compile(r"Benchmark version:\s*([^,]+)")
DATE_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{1,2})")

CATEGORY_LABELS = {
    "cmdi": "Command Injection",
    "crypto": "Weak Encryption Algorithm",
    "hash": "Weak Hash Algorithm",
    "ldapi": "LDAP Injection",
    "pathtraver": "Path Traversal",
    "securecookie": "Insecure Cookie",
    "sqli": "SQL Injection",
    "trustbound": "Trust Boundary Violation",
    "weakrand": "Weak Random Number",
    "xpathi": "XPath Injection",
    "xss": "Cross-Site Scripting",
}

CATEGORY_RULE_PATTERNS = {
    "cmdi": (
        "command injection",
        "命令注入",
        "runtime.getruntime().exec",
        "processbuilder",
    ),
    "crypto": (
        "weak encryption",
        "weak cryptography",
        "不安全加密",
        "弱加密",
        "硬编码加密",
        "hard coded encryption",
        "des",
        "3des",
        "rc2",
        "rc4",
        "blowfish",
        "ecb",
        "iv",
        "cbc",
    ),
    "hash": (
        "weak hash",
        "弱哈希",
        "弱散列",
        "md5",
        "sha1",
        "sha-1",
        "digest",
    ),
    "ldapi": (
        "ldap injection",
        "ldap注入",
    ),
    "pathtraver": (
        "path traversal",
        "path manipulation",
        "路径遍历",
        "路径穿越",
        "file download",
        "file deletion",
    ),
    "securecookie": (
        "secure cookie",
        "cookie secure",
        "insecure cookie",
        "cookie 安全",
        "cookie secure flag",
        "secure flag",
    ),
    "sqli": (
        "sql injection",
        "sql注入",
        "mybatis",
        "jdbc",
        "hql injection",
    ),
    "trustbound": (
        "trust boundary",
        "边界违反",
        "untrusted input",
        "security decision",
        "reliance on untrusted inputs",
        "fake ip",
        "xff",
        "x-forwarded-for",
        "host header",
    ),
    "weakrand": (
        "weak random",
        "弱随机",
        "不安全随机数",
        "predictable random",
        "insecure randomness",
        "java.util.random",
        "secure random",
    ),
    "xpathi": (
        "xpath injection",
        "xpath注入",
        "xpath",
    ),
    "xss": (
        "xss",
        "cross-site scripting",
        "XSS",
        "response body xss",
        "template xss",
        "servlet xss",
    ),
}

OWASP_BENCHMARK_RULE_GROUPS = [
    "OWASP 2021 A01:Broken Access Control",
    "OWASP 2021 A02:Cryptographic Failures",
    "OWASP 2021 A03:Injection",
    "OWASP 2021 A05:Security Misconfiguration",
    "OWASP 2021 A07:Identification and Authentication Failures",
    "OWASP 2021 A08:Software and Data Integrity Failures",
]

CATEGORY_SCAN_KEYWORDS = {
    "cmdi": "command",
    "crypto": "encrypt",
    "hash": "hash",
    "ldapi": "ldap",
    "pathtraver": "path",
    "securecookie": "cookie",
    "sqli": "sql",
    "trustbound": "xff",
    "weakrand": "random",
    "xpathi": "xpath",
    "xss": "xss",
}

SCAN_CHUNK_SIZE = 100


def run_owasp_benchmark(
    benchmark_root: Path,
    out_dir: Path,
    expected_results_path: Path | None = None,
    scan_json_path: Path | None = None,
    skip_scan: bool = False,
) -> dict[str, Any]:
    benchmark_root = benchmark_root.resolve()
    out_dir = ensure_dir(out_dir.resolve())
    expected_results_path = (expected_results_path or find_expected_results(benchmark_root)).resolve()
    expected_rows, metadata = load_expected_results(expected_results_path)

    if not skip_scan:
        manifest = run_category_scans(benchmark_root, expected_rows, out_dir / "raw")
        scan_json_path = out_dir / "irify-scan-manifest.json"
        write_json(scan_json_path, manifest)
        findings_payload = merge_findings_payloads(manifest, metadata)
    else:
        scan_json_path = (scan_json_path or out_dir / "irify-scan.json").resolve()
        if not scan_json_path.exists():
            raise FileNotFoundError(f"scan json not found: {scan_json_path}")
        findings_payload = parse_irify_json(scan_json_path, "OWASP Benchmark")
    findings_path = out_dir / "irify-findings.json"
    write_json(findings_path, findings_payload)

    evaluation = evaluate_owasp_benchmark(expected_results_path, benchmark_root, findings_payload)
    evaluation_path = out_dir / "owasp-benchmark-eval.json"
    write_json(evaluation_path, evaluation)

    actual_results_path = out_dir / "owasp-benchmark-actual-results.csv"
    write_actual_results_csv(actual_results_path, evaluation)

    report_path = out_dir / "owasp-benchmark-scorecard.md"
    report_path.write_text(render_markdown_report(evaluation, actual_results_path), encoding="utf-8")

    return {
        "benchmark_root": str(benchmark_root),
        "expected_results": str(expected_results_path),
        "scan_json": str(scan_json_path),
        "findings_json": str(findings_path),
        "evaluation_json": str(evaluation_path),
        "actual_results_csv": str(actual_results_path),
        "report_markdown": str(report_path),
        "overall_score_100": evaluation["summary"]["overall_score_100"],
        "overall_tpr": evaluation["summary"]["overall_tpr"],
        "overall_fpr": evaluation["summary"]["overall_fpr"],
    }


def evaluate_owasp_benchmark(
    expected_results_path: Path,
    benchmark_root: Path,
    findings_payload: dict[str, Any],
) -> dict[str, Any]:
    expected_rows, metadata = load_expected_results(expected_results_path)
    return evaluate_owasp_benchmark_rows(expected_rows, metadata, benchmark_root, findings_payload)


def evaluate_owasp_benchmark_rows(
    expected_rows: list[dict[str, Any]],
    metadata: dict[str, Any],
    benchmark_root: Path,
    findings_payload: dict[str, Any],
) -> dict[str, Any]:
    source_index = index_test_sources(benchmark_root)
    testcase_findings = group_findings_by_test(findings_payload.get("findings", []))

    cases: list[dict[str, Any]] = []
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    matched_finding_count = 0
    same_file_finding_count = 0

    for row in expected_rows:
        test_name = row["test_name"]
        all_same_file = testcase_findings.get(test_name, [])
        matched_findings = [finding for finding in all_same_file if finding_matches_category(finding, row["category"])]
        same_file_finding_count += len(all_same_file)
        matched_finding_count += len(matched_findings)
        reported = bool(matched_findings)
        same_file_reported = bool(all_same_file)
        case = {
            "test_name": test_name,
            "category": row["category"],
            "category_label": CATEGORY_LABELS.get(row["category"], row["category"]),
            "cwe": row["cwe"],
            "expected_vulnerability": row["real_vulnerability"],
            "reported_by_tool": reported,
            "same_file_reported": same_file_reported,
            "pass": reported == row["real_vulnerability"],
            "file_path": source_index.get(test_name, default_test_path(test_name)),
            "matched_rules": unique_strings(rule_name(finding) for finding in matched_findings),
            "same_file_rules": unique_strings(rule_name(finding) for finding in all_same_file),
            "matched_lines": unique_ints(int(finding.get("line_start", 0) or 0) for finding in matched_findings),
            "same_file_lines": unique_ints(int(finding.get("line_start", 0) or 0) for finding in all_same_file),
            "matched_findings": sanitize_findings(matched_findings),
            "same_file_findings": sanitize_findings(all_same_file),
        }
        buckets[row["category"]].append(case)
        cases.append(case)

    categories = [summarize_category(category, items) for category, items in sorted(buckets.items())]
    summary = summarize_overall(categories, cases, len(findings_payload.get("findings", [])), same_file_finding_count, matched_finding_count)
    return {
        "project": "OWASP Benchmark",
        "tool": "irify",
        "metadata": {
            **metadata,
            "benchmark_root": str(benchmark_root),
        },
        "summary": summary,
        "categories": categories,
        "cases": cases,
    }


def build_findings_payload_from_raw_files(paths: list[Path], metadata: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scans: list[dict[str, Any]] = []
    for path in paths:
        parsed = parse_irify_json(path, "OWASP Benchmark")
        findings.extend(parsed.get("findings", []))
        scans.append({"output": str(path), "findings_count": parsed.get("findings_count", 0)})
    deduped = deduplicate_findings(findings)
    return {
        "tool": "irify",
        "project": "OWASP Benchmark",
        "source": "partial_raw_merge_v1",
        "summary": {
            "risk_count": len(deduped),
            "counts": count_by_severity(deduped),
            "chunk_scan_count": len(scans),
            "benchmark_version": metadata.get("benchmark_version", ""),
        },
        "findings_count": len(deduped),
        "findings": deduped,
        "raw_scans": scans,
    }


def load_expected_results(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    header = ""
    with path.open(encoding="utf-8") as handle:
        reader = csv.reader(handle)
        for raw in reader:
            if not raw:
                continue
            first = str(raw[0]).strip()
            if first.startswith("#"):
                if not header:
                    header = ",".join(raw)
                continue
            if len(raw) < 4:
                continue
            rows.append(
                {
                    "test_name": str(raw[0]).strip(),
                    "category": str(raw[1]).strip(),
                    "real_vulnerability": str(raw[2]).strip().lower() == "true",
                    "cwe": int(str(raw[3]).strip()),
                }
            )
    version_match = VERSION_PATTERN.search(header)
    date_match = DATE_PATTERN.search(header)
    return rows, {
        "expected_results_header": header,
        "benchmark_version": version_match.group(1).strip() if version_match else "",
        "benchmark_header_date": date_match.group(1) if date_match else "",
        "case_count": len(rows),
        "category_count": len({row["category"] for row in rows}),
    }


def find_expected_results(benchmark_root: Path) -> Path:
    candidates = sorted(benchmark_root.glob("expectedresults-*.csv"))
    if not candidates:
        raise FileNotFoundError(f"expectedresults-*.csv not found under {benchmark_root}")
    return candidates[-1]


def run_irify_scan(benchmark_root: Path, output_path: Path, logs_dir: Path) -> None:
    scan_target = benchmark_root / "src/main/java/org/owasp/benchmark/testcode"
    if not scan_target.exists():
        scan_target = benchmark_root
    run_irify_scan_targets([scan_target], output_path, logs_dir, None, "full")


def run_category_scans(benchmark_root: Path, expected_rows: list[dict[str, Any]], raw_dir: Path) -> dict[str, Any]:
    raw_dir = ensure_dir(raw_dir)
    logs_dir = ensure_dir(raw_dir / "logs")
    source_index = index_test_sources(benchmark_root)
    rows_by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in expected_rows:
        rows_by_category[row["category"]].append(row)

    scans: list[dict[str, Any]] = []
    for category, rows in sorted(rows_by_category.items()):
        files = [
            benchmark_root / source_index[row["test_name"]]
            for row in rows
            if row["test_name"] in source_index
        ]
        keyword = CATEGORY_SCAN_KEYWORDS.get(category)
        for index, chunk in enumerate(chunked(files, SCAN_CHUNK_SIZE), start=1):
            output_path = raw_dir / f"{category}-part{index:02d}.json"
            try:
                parsed = parse_irify_json(output_path, "OWASP Benchmark") if output_path.exists() else None
            except Exception:
                parsed = None
            if parsed is None:
                run_irify_scan_targets(chunk, output_path, logs_dir, keyword, f"{category}-part{index:02d}")
                parsed = parse_irify_json(output_path, "OWASP Benchmark")
            scans.append(
                {
                    "category": category,
                    "part": index,
                    "target_count": len(chunk),
                    "keyword": keyword or "",
                    "output": str(output_path),
                    "findings_count": parsed["findings_count"],
                }
            )
    return {
        "project": "OWASP Benchmark",
        "source": "chunked_category_scan_v1",
        "chunk_size": SCAN_CHUNK_SIZE,
        "scans": scans,
    }


def run_irify_scan_targets(
    targets: list[Path],
    output_path: Path,
    logs_dir: Path,
    rule_keyword: str | None,
    label: str,
) -> None:
    ensure_dir(output_path.parent)
    target_value = ",".join(str(path.resolve()) for path in targets)
    cmd = [
        "go",
        "run",
        "./common/yak/cmd/yak.go",
        "code-scan",
        "--target",
        target_value,
        "--language",
        "java",
        "--memory",
        "--format",
        "irify",
        "--output",
        str(output_path),
        "--log-level",
        "info",
    ]
    if rule_keyword:
        cmd.extend(["--rule-keyword", rule_keyword])
    stdout_path = logs_dir / f"{label}.stdout.log"
    stderr_path = logs_dir / f"{label}.stderr.log"
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
        subprocess.run(cmd, cwd=REPO_ROOT / "yaklang", check=True, stdout=stdout, stderr=stderr)


def merge_findings_payloads(manifest: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for scan in manifest.get("scans", []):
        parsed = parse_irify_json(Path(scan["output"]), "OWASP Benchmark")
        findings.extend(parsed.get("findings", []))
    deduped = deduplicate_findings(findings)
    return {
        "tool": "irify",
        "project": "OWASP Benchmark",
        "source": "chunked_category_scan_v1",
        "summary": {
            "risk_count": len(deduped),
            "counts": count_by_severity(deduped),
            "chunk_scan_count": len(manifest.get("scans", [])),
            "benchmark_version": metadata.get("benchmark_version", ""),
        },
        "findings_count": len(deduped),
        "findings": deduped,
        "raw_scans": manifest.get("scans", []),
    }


def index_test_sources(benchmark_root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in benchmark_root.rglob("BenchmarkTest*.java"):
        result[path.stem] = path.relative_to(benchmark_root).as_posix()
    return result


def group_findings_by_test(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        test_name = extract_test_name(str(finding.get("file_path") or ""))
        if not test_name:
            continue
        grouped[test_name].append(finding)
    return grouped


def extract_test_name(file_path: str) -> str:
    match = TEST_NAME_PATTERN.search(file_path or "")
    return match.group(1) if match else ""


def finding_matches_category(finding: dict[str, Any], category: str) -> bool:
    tokens = CATEGORY_RULE_PATTERNS.get(category, ())
    text = " ".join(
        str(finding.get(key) or "")
        for key in ("rule_type", "rule_name", "title", "evidence")
    ).lower()
    return any(token in text for token in tokens)


def summarize_category(category: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(1 for case in cases if case["expected_vulnerability"] and case["reported_by_tool"])
    fn = sum(1 for case in cases if case["expected_vulnerability"] and not case["reported_by_tool"])
    fp = sum(1 for case in cases if (not case["expected_vulnerability"]) and case["reported_by_tool"])
    tn = sum(1 for case in cases if (not case["expected_vulnerability"]) and (not case["reported_by_tool"]))
    same_file_tp = sum(1 for case in cases if case["expected_vulnerability"] and case["same_file_reported"])
    same_file_fn = sum(1 for case in cases if case["expected_vulnerability"] and not case["same_file_reported"])
    same_file_fp = sum(1 for case in cases if (not case["expected_vulnerability"]) and case["same_file_reported"])
    same_file_tn = sum(1 for case in cases if (not case["expected_vulnerability"]) and (not case["same_file_reported"]))
    tpr = ratio(tp, tp + fn)
    fpr = ratio(fp, fp + tn)
    score = None if tpr is None or fpr is None else round(tpr - fpr, 4)
    same_file_tpr = ratio(same_file_tp, same_file_tp + same_file_fn)
    same_file_fpr = ratio(same_file_fp, same_file_fp + same_file_tn)
    same_file_score = None if same_file_tpr is None or same_file_fpr is None else round(same_file_tpr - same_file_fpr, 4)
    return {
        "category": category,
        "category_label": CATEGORY_LABELS.get(category, category),
        "case_count": len(cases),
        "positive_cases": sum(1 for case in cases if case["expected_vulnerability"]),
        "negative_cases": sum(1 for case in cases if not case["expected_vulnerability"]),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "tpr": tpr,
        "fpr": fpr,
        "score": score,
        "same_file_tp": same_file_tp,
        "same_file_fn": same_file_fn,
        "same_file_fp": same_file_fp,
        "same_file_tn": same_file_tn,
        "same_file_tpr": same_file_tpr,
        "same_file_fpr": same_file_fpr,
        "same_file_score": same_file_score,
    }


def summarize_overall(
    categories: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    total_findings: int,
    same_file_finding_count: int,
    matched_finding_count: int,
) -> dict[str, Any]:
    total_tp = sum(item["tp"] for item in categories)
    total_fn = sum(item["fn"] for item in categories)
    total_fp = sum(item["fp"] for item in categories)
    total_tn = sum(item["tn"] for item in categories)
    micro_tpr = ratio(total_tp, total_tp + total_fn)
    micro_fpr = ratio(total_fp, total_fp + total_tn)
    micro_score = None if micro_tpr is None or micro_fpr is None else round(micro_tpr - micro_fpr, 4)
    official_tpr = average(item["tpr"] for item in categories)
    official_fpr = average(item["fpr"] for item in categories)
    official_score = average(item["score"] for item in categories)
    same_file_tpr = average(item["same_file_tpr"] for item in categories)
    same_file_fpr = average(item["same_file_fpr"] for item in categories)
    same_file_score = average(item["same_file_score"] for item in categories)
    return {
        "category_count": len(categories),
        "case_count": len(cases),
        "positive_cases": sum(1 for case in cases if case["expected_vulnerability"]),
        "negative_cases": sum(1 for case in cases if not case["expected_vulnerability"]),
        "total_findings": total_findings,
        "benchmark_test_findings": same_file_finding_count,
        "category_matched_findings": matched_finding_count,
        "tp": total_tp,
        "fn": total_fn,
        "fp": total_fp,
        "tn": total_tn,
        "micro_tpr": micro_tpr,
        "micro_fpr": micro_fpr,
        "micro_score": micro_score,
        "overall_tpr": official_tpr,
        "overall_fpr": official_fpr,
        "overall_score": official_score,
        "overall_score_100": None if official_score is None else round(official_score * 100, 2),
        "same_file_overall_tpr": same_file_tpr,
        "same_file_overall_fpr": same_file_fpr,
        "same_file_overall_score": same_file_score,
        "same_file_overall_score_100": None if same_file_score is None else round(same_file_score * 100, 2),
    }


def write_actual_results_csv(path: Path, evaluation: dict[str, Any]) -> None:
    ensure_dir(path.parent)
    version = evaluation.get("metadata", {}).get("benchmark_version", "")
    header = f"# test name, category, CWE, real vulnerability, identified by tool, pass/fail, Benchmark version: {version}, Actual results generated by IRify"
    lines = [header]
    for case in evaluation.get("cases", []):
        lines.append(
            ", ".join(
                [
                    case["test_name"],
                    case["category"],
                    str(case["cwe"]),
                    bool_text(case["expected_vulnerability"]),
                    bool_text(case["reported_by_tool"]),
                    "pass" if case["pass"] else "fail",
                ]
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render_markdown_report(evaluation: dict[str, Any], actual_results_path: Path) -> str:
    meta = evaluation["metadata"]
    summary = evaluation["summary"]
    lines = [
        "# OWASP Benchmark 评测结果",
        "",
        "## 基线",
        f"- Benchmark 版本：`{meta.get('benchmark_version') or '-'}`",
        f"- Header 日期：`{meta.get('benchmark_header_date') or '-'}`",
        f"- 用例总数：`{summary['case_count']}`",
        f"- 类别数：`{summary['category_count']}`",
        f"- 扫描 finding 总数：`{summary['total_findings']}`",
        f"- 落在 Benchmark testcase 文件上的 finding：`{summary['benchmark_test_findings']}`",
        f"- 同时匹配 testcase + category 的 finding：`{summary['category_matched_findings']}`",
        f"- 实际结果 CSV：`{actual_results_path}`",
        "",
        "## 官方口径总览",
        "",
        "| 指标 | 数值 |",
        "| --- | ---: |",
        f"| 平均 TPR | {format_ratio(summary['overall_tpr'])} |",
        f"| 平均 FPR | {format_ratio(summary['overall_fpr'])} |",
        f"| 平均 Score | {format_ratio(summary['overall_score'])} |",
        f"| 官方总分（0-100） | {format_score(summary['overall_score_100'])} |",
        f"| 微平均 TPR | {format_ratio(summary['micro_tpr'])} |",
        f"| 微平均 FPR | {format_ratio(summary['micro_fpr'])} |",
        f"| 微平均 Score | {format_ratio(summary['micro_score'])} |",
        f"| 同文件宽松总分（0-100） | {format_score(summary['same_file_overall_score_100'])} |",
        "",
        "## 分类得分卡",
        "",
        "| 类别 | 正例 | 负例 | TP | FN | FP | TN | TPR | FPR | Score | 同文件 Score |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in evaluation["categories"]:
        lines.append(
            "| {label} | {pos} | {neg} | {tp} | {fn} | {fp} | {tn} | {tpr} | {fpr} | {score} | {same_file_score} |".format(
                label=item["category_label"],
                pos=item["positive_cases"],
                neg=item["negative_cases"],
                tp=item["tp"],
                fn=item["fn"],
                fp=item["fp"],
                tn=item["tn"],
                tpr=format_ratio(item["tpr"]),
                fpr=format_ratio(item["fpr"]),
                score=format_ratio(item["score"]),
                same_file_score=format_ratio(item["same_file_score"]),
            )
        )
    misses = [case for case in evaluation["cases"] if case["expected_vulnerability"] and not case["reported_by_tool"]][:40]
    false_positives = [case for case in evaluation["cases"] if (not case["expected_vulnerability"]) and case["reported_by_tool"]][:40]
    lines.extend(
        [
            "",
            "## 重点漏报（前 40）",
            "",
            "| Test | 类别 | 文件 | 同文件命中 | 同文件规则 |",
            "| --- | --- | --- | ---: | --- |",
        ]
    )
    if misses:
        for case in misses:
            lines.append(
                "| {test} | {category} | `{file}` | {same_file} | {rules} |".format(
                    test=case["test_name"],
                    category=case["category_label"],
                    file=case["file_path"],
                    same_file="是" if case["same_file_reported"] else "否",
                    rules=" / ".join(case["same_file_rules"][:3]) or "-",
                )
            )
    else:
        lines.append("| - | - | - | - | - |")
    lines.extend(
        [
            "",
            "## 重点误报（前 40）",
            "",
            "| Test | 类别 | 文件 | 匹配规则 |",
            "| --- | --- | --- | --- |",
        ]
    )
    if false_positives:
        for case in false_positives:
            lines.append(
                "| {test} | {category} | `{file}` | {rules} |".format(
                    test=case["test_name"],
                    category=case["category_label"],
                    file=case["file_path"],
                    rules=" / ".join(case["matched_rules"][:3]) or "-",
                )
            )
    else:
        lines.append("| - | - | - | - |")
    lines.extend(
        [
            "",
            "## 评分公式",
            "",
            "- `TPR = TP / (TP + FN)`",
            "- `FPR = FP / (FP + TN)`",
            "- `Score = TPR - FPR`",
            "- 官方总分取各漏洞类别 `Score` 的简单平均，再乘 `100`。",
        ]
    )
    return "\n".join(lines) + "\n"


def render_html_report(evaluation: dict[str, Any], actual_results_path: Path, output_path: Path, report_title: str) -> str:
    summary = evaluation["summary"]
    category_rows = []
    for item in evaluation["categories"]:
        category_rows.append(
            "<tr>"
            f"<td>{item['category_label']}</td>"
            f"<td>{item['positive_cases']}</td>"
            f"<td>{item['negative_cases']}</td>"
            f"<td>{item['tp']}</td>"
            f"<td>{item['fn']}</td>"
            f"<td>{item['fp']}</td>"
            f"<td>{item['tn']}</td>"
            f"<td>{format_ratio(item['tpr'])}</td>"
            f"<td>{format_ratio(item['fpr'])}</td>"
            f"<td>{format_ratio(item['score'])}</td>"
            "</tr>"
        )
    miss_rows = []
    misses = [case for case in evaluation["cases"] if case["expected_vulnerability"] and not case["reported_by_tool"]][:50]
    for case in misses:
        miss_rows.append(
            "<tr>"
            f"<td>{case['test_name']}</td>"
            f"<td>{case['category_label']}</td>"
            f"<td><code>{case['file_path']}</code></td>"
            f"<td>{'是' if case['same_file_reported'] else '否'}</td>"
            f"<td>{' / '.join(case['same_file_rules'][:3]) or '-'}</td>"
            "</tr>"
        )
    fp_rows = []
    false_positives = [case for case in evaluation["cases"] if (not case["expected_vulnerability"]) and case["reported_by_tool"]][:50]
    for case in false_positives:
        fp_rows.append(
            "<tr>"
            f"<td>{case['test_name']}</td>"
            f"<td>{case['category_label']}</td>"
            f"<td><code>{case['file_path']}</code></td>"
            f"<td>{' / '.join(case['matched_rules'][:3]) or '-'}</td>"
            "</tr>"
        )
    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>{report_title}</title>
  <style>
    body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#0b1020; color:#e8edf7; margin:0; }}
    .wrap {{ max-width: 1280px; margin:0 auto; padding:32px; }}
    .cards {{ display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:16px; margin:20px 0 28px; }}
    .card {{ background:#121a31; border:1px solid #243355; border-radius:16px; padding:18px; }}
    .label {{ color:#8ea2ca; font-size:13px; }}
    .value {{ font-size:28px; font-weight:700; margin-top:6px; }}
    table {{ width:100%; border-collapse:collapse; margin:16px 0 28px; background:#121a31; }}
    th,td {{ padding:12px 14px; border-bottom:1px solid #22304f; text-align:left; vertical-align:top; font-size:14px; }}
    th {{ background:#16203c; }}
    code {{ color:#b8d3ff; }}
    .note {{ background:#0f1730; border-left:4px solid #4aa3ff; padding:14px 16px; border-radius:10px; margin:20px 0; }}
  </style>
</head>
<body>
<div class="wrap">
  <h1>{report_title}</h1>
  <div class="note">
    <p>当前为部分结果预览，只包含已完成扫描类别，不代表全量 OWASP Benchmark 最终得分。</p>
    <p>Actual results CSV：<code>{actual_results_path}</code></p>
  </div>
  <div class="cards">
    <div class="card"><div class="label">已评估类别</div><div class="value">{summary['category_count']}</div></div>
    <div class="card"><div class="label">已评估用例</div><div class="value">{summary['case_count']}</div></div>
    <div class="card"><div class="label">部分 Score(0-100)</div><div class="value">{format_score(summary['overall_score_100'])}</div></div>
    <div class="card"><div class="label">部分 TPR / FPR</div><div class="value">{format_ratio(summary['overall_tpr'])} / {format_ratio(summary['overall_fpr'])}</div></div>
  </div>
  <h2>分类得分</h2>
  <table>
    <thead><tr><th>类别</th><th>正例</th><th>负例</th><th>TP</th><th>FN</th><th>FP</th><th>TN</th><th>TPR</th><th>FPR</th><th>Score</th></tr></thead>
    <tbody>{''.join(category_rows)}</tbody>
  </table>
  <h2>重点漏报</h2>
  <table>
    <thead><tr><th>Test</th><th>类别</th><th>文件</th><th>同文件命中</th><th>同文件规则</th></tr></thead>
    <tbody>{''.join(miss_rows) or '<tr><td colspan="5">无</td></tr>'}</tbody>
  </table>
  <h2>重点误报</h2>
  <table>
    <thead><tr><th>Test</th><th>类别</th><th>文件</th><th>匹配规则</th></tr></thead>
    <tbody>{''.join(fp_rows) or '<tr><td colspan="4">无</td></tr>'}</tbody>
  </table>
</div>
</body>
</html>
"""
    output_path.write_text(html, encoding="utf-8")
    return html


def sanitize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for finding in findings:
        result.append(
            {
                "rule_name": rule_name(finding),
                "severity": finding.get("severity"),
                "line_start": int(finding.get("line_start", 0) or 0),
                "evidence": str(finding.get("evidence") or "")[:300],
            }
        )
    return result


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str, str]] = set()
    for finding in findings:
        key = (
            str(finding.get("file_path") or ""),
            int(finding.get("line_start", 0) or 0),
            rule_name(finding),
            str(finding.get("severity") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "").lower()
        if severity == "middle":
            severity = "medium"
        if severity in counts:
            counts[severity] += 1
    return counts


def rule_name(finding: dict[str, Any]) -> str:
    return str(finding.get("rule_type") or finding.get("rule_name") or finding.get("title") or "Unknown")


def default_test_path(test_name: str) -> str:
    return f"src/main/java/org/owasp/benchmark/testcode/{test_name}.java"


def ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def average(values: Any) -> float | None:
    items = [value for value in values if value is not None]
    if not items:
        return None
    return round(sum(items) / len(items), 4)


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def format_ratio(value: float | None) -> str:
    return "-" if value is None else f"{value:.4f}"


def format_score(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}"


def unique_strings(values: Any) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def unique_ints(values: Any) -> list[int]:
    result: list[int] = []
    seen: set[int] = set()
    for value in values:
        if value <= 0 or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def chunked(items: list[Path], size: int) -> list[list[Path]]:
    return [items[index : index + size] for index in range(0, len(items), size)]
