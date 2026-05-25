from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .matcher import match_annotations
from .utils import ensure_dir, read_yaml


def generate_project_report(
    manifest_path: Path,
    project_name: str,
    annotations_path: Path,
    fortify_result: dict[str, Any],
    code_guard_result: dict[str, Any],
    out_path: Path,
) -> str:
    manifest = read_yaml(manifest_path)
    project = find_project(manifest, project_name)
    annotations_doc = read_yaml(annotations_path)
    annotations = annotations_doc.get("annotations") or annotations_doc.get("cases") or []
    fortify_match = match_annotations(annotations, fortify_result["findings"])
    code_guard_match = match_annotations(annotations, code_guard_result["findings"])
    content = render_markdown(project, annotations, fortify_result, code_guard_result, fortify_match, code_guard_match)
    ensure_dir(out_path.parent)
    out_path.write_text(content, encoding="utf-8")
    return content


def generate_project_html_report(
    manifest_path: Path,
    project_name: str,
    annotations_path: Path,
    fortify_result: dict[str, Any],
    code_guard_result: dict[str, Any],
    irify_result: dict[str, Any],
    out_path: Path,
    irify_runtime: dict[str, Any] | None = None,
) -> str:
    manifest = read_yaml(manifest_path)
    project = find_project(manifest, project_name)
    annotations_doc = read_yaml(annotations_path)
    annotations = annotations_doc.get("annotations") or annotations_doc.get("cases") or []
    fortify_match = match_annotations(annotations, fortify_result["findings"])
    code_guard_match = match_annotations(annotations, code_guard_result["findings"])
    irify_match = match_annotations(annotations, irify_result["findings"])
    html = render_html(project, fortify_result, code_guard_result, irify_result, fortify_match, code_guard_match, irify_match, annotations, irify_runtime or {})
    ensure_dir(out_path.parent)
    out_path.write_text(html, encoding="utf-8")
    return html


def find_project(manifest: dict[str, Any], project_name: str) -> dict[str, Any]:
    for project in manifest.get("projects", []):
        if project.get("name") == project_name or project.get("id") == project_name:
            return project
    raise KeyError(f"project not found: {project_name}")


def render_markdown(
    project: dict[str, Any],
    annotations: list[dict[str, Any]],
    fortify_result: dict[str, Any],
    code_guard_result: dict[str, Any],
    fortify_match: dict[str, Any],
    code_guard_match: dict[str, Any],
) -> str:
    lines: list[str] = []
    lines.append(f"# {project['name']} Benchmark 对比报告")
    lines.append("")
    lines.append("## 项目输入")
    lines.append(f"- GitHub：{project.get('github_url')}")
    lines.append(f"- 语言：{project.get('language')}")
    lines.append(f"- 源码包：`{project.get('source_package')}`")
    lines.append(f"- Fortify 报告：`{project.get('reports', {}).get('fortify')}`")
    lines.append(f"- 代码卫士报告：`{project.get('reports', {}).get('code_guard')}`")
    lines.append("")
    lines.append("## 原始汇总口径")
    lines.append("| 工具 | 严重 | 高危 | 中危 | 低危 | 信息 | 时间 |")
    lines.append("|---|---:|---:|---:|---:|---:|---|")
    for tool, label in [("fortify", "Fortify"), ("code_guard", "代码卫士"), ("irify", "IRify")]:
        counts = project.get("reported_counts", {}).get(tool, {})
        time_key = {"fortify": "fortify", "code_guard": "code_guard", "irify": "irify_compile_scan"}[tool]
        lines.append(
            f"| {label} | {counts.get('critical', 0)} | {counts.get('high', 0)} | "
            f"{counts.get('medium', 0)} | {counts.get('low', 0)} | {counts.get('info', 0)} | "
            f"{project.get('reported_time', {}).get(time_key, '')} |"
        )
    lines.append("")
    lines.append("## 解析结果")
    lines.append("| 工具 | 解析 finding 数 | Top 规则 |")
    lines.append("|---|---:|---|")
    lines.append(f"| Fortify | {fortify_result['findings_count']} | {top_rules(fortify_result['findings'])} |")
    lines.append(f"| 代码卫士 | {code_guard_result['findings_count']} | {top_rules(code_guard_result['findings'])} |")
    lines.append("")
    lines.append("## 样例人工真值集匹配")
    lines.append("| 工具 | 标注数 | 命中 TP | 未命中 FN | 样例召回率 | 未审计 finding |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    lines.append(match_row("Fortify", fortify_match))
    lines.append(match_row("代码卫士", code_guard_match))
    lines.append("")
    lines.append("> 当前人工标注只是 JavaSecLab 样例子集，未审计 finding 不直接等价于误报。后续补齐全量人工真值后，才能输出正式 Precision / Recall / F1。")
    lines.append("")
    lines.append("## 样例标注")
    lines.append("| case_id | 规则 | 文件 | 行 | 证据 |")
    lines.append("|---|---|---|---:|---|")
    for annotation in annotations:
        lines.append(
            f"| {annotation.get('case_id')} | {annotation.get('rule_type')} | "
            f"`{annotation.get('file_path')}` | {annotation.get('line_start')} | {annotation.get('evidence', '')} |"
        )
    lines.append("")
    lines.append("## 下一步")
    lines.append("- 将样例标注扩展成全量 JavaSecLab 真值集。")
    lines.append("- 接入 IRify finding 级 JSON 后，补齐 IRify 的 TP/FP/FN。")
    lines.append("- 对 PDF/DOCX 解析结果进入人工复核流程，确认竞品误报。")
    return "\n".join(lines) + "\n"


def render_html(
    project: dict[str, Any],
    fortify_result: dict[str, Any],
    code_guard_result: dict[str, Any],
    irify_result: dict[str, Any],
    fortify_match: dict[str, Any],
    code_guard_match: dict[str, Any],
    irify_match: dict[str, Any],
    annotations: list[dict[str, Any]],
    irify_runtime: dict[str, Any],
) -> str:
    historical_irify = project.get("reported_counts", {}).get("irify", {})
    current_irify = irify_result.get("summary", {}).get("counts", {})
    severity_rows = ["critical", "high", "medium", "low", "info"]
    tools = [
        ("Fortify", fortify_result.get("summary", {}).get("counts", {}), project.get("reported_time", {}).get("fortify", ""), fortify_match),
        ("代码卫士", code_guard_result.get("summary", {}).get("counts", {}), project.get("reported_time", {}).get("code_guard", ""), code_guard_match),
        ("IRify-本次CLI扫描", current_irify, irify_runtime.get("elapsed", ""), irify_match),
        ("IRify-历史表格口径", historical_irify, project.get("reported_time", {}).get("irify_compile_scan", ""), None),
    ]
    max_count = max(max(counts.get(key, 0) for key in severity_rows) for _, counts, _, _ in tools) or 1

    cards = [
        stat_card("Fortify findings", str(fortify_result["findings_count"])),
        stat_card("代码卫士 findings", str(code_guard_result["findings_count"])),
        stat_card("IRify findings", str(irify_result["findings_count"])),
        stat_card("IRify 扫描耗时", irify_runtime.get("elapsed", "未知")),
        stat_card("IRify 最大内存", irify_runtime.get("maxrss", "未知")),
        stat_card("IRify 失败规则", str(irify_runtime.get("failed_rules", "未知"))),
    ]

    tool_rows = []
    for label, counts, elapsed, match in tools:
        recall = "-" if not match or match.get("sample_recall") is None else f"{match['sample_recall'] * 100:.1f}%"
        tool_rows.append(
            "<tr>"
            f"<td>{label}</td>"
            + "".join(f"<td>{counts.get(key, 0)}</td>" for key in severity_rows)
            + f"<td>{elapsed}</td><td>{recall}</td>"
            "</tr>"
        )

    bars = []
    colors = {"critical": "#d14343", "high": "#e67e22", "medium": "#f1c40f", "low": "#3498db", "info": "#7f8c8d"}
    for severity in severity_rows:
        bars.append(f"<div class='severity-group'><h4>{severity.upper()}</h4>")
        for label, counts, _, _ in tools:
            value = counts.get(severity, 0)
            width = int(value / max_count * 100)
            bars.append(
                "<div class='bar-row'>"
                f"<span class='bar-label'>{label}</span>"
                f"<div class='bar-track'><div class='bar-fill' style='width:{max(width, 1 if value else 0)}%;background:{colors[severity]}'></div></div>"
                f"<span class='bar-value'>{value}</span>"
                "</div>"
            )
        bars.append("</div>")

    annotation_rows = []
    for annotation in annotations:
        annotation_rows.append(
            "<tr>"
            f"<td>{annotation.get('case_id')}</td>"
            f"<td>{annotation.get('rule_type')}</td>"
            f"<td><code>{annotation.get('file_path')}</code></td>"
            f"<td>{annotation.get('line_start')}</td>"
            f"<td>{annotation.get('evidence')}</td>"
            "</tr>"
        )

    unmatched_rows = []
    for label, result in [("Fortify", fortify_match), ("代码卫士", code_guard_match), ("IRify", irify_match)]:
        items = result.get("unmatched_annotations", [])
        unmatched_rows.append(
            "<tr>"
            f"<td>{label}</td>"
            f"<td>{', '.join(item.get('case_id', '') for item in items) or '-'}</td>"
            f"<td>{len(items)}</td>"
            "</tr>"
        )

    insight_items = [
        f"Fortify 当前解析到 {fortify_result['findings_count']} 条 finding，样例召回 {percent(fortify_match.get('sample_recall'))}。",
        f"代码卫士当前解析到 {code_guard_result['findings_count']} 条 finding，样例召回 {percent(code_guard_match.get('sample_recall'))}。",
        f"IRify 本次 CLI 内存扫描得到 {irify_result['findings_count']} 条 finding，样例召回 {percent(irify_match.get('sample_recall'))}。",
        f"IRify 当前高危/中危/低危分别为 {current_irify.get('high', 0)}/{current_irify.get('medium', 0)}/{current_irify.get('low', 0)}，高于历史表格口径 {historical_irify.get('high', 0)}/{historical_irify.get('medium', 0)}/{historical_irify.get('low', 0)}，说明规则集或版本口径已发生变化。",
        f"IRify 本次扫描日志显示失败规则 {irify_runtime.get('failed_rules', '未知')} 条，需复核 `检测 Java XMLReaderFactory 不安全使用` 对结果覆盖面的影响。",
    ]

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>{project['name']} Benchmark 对比报告</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#0b1020; color:#e8edf7; margin:0; }}
    .wrap {{ max-width: 1280px; margin: 0 auto; padding: 32px; }}
    h1, h2, h3, h4 {{ margin: 0 0 12px; }}
    p, li {{ line-height: 1.6; }}
    .muted {{ color:#9fb0d1; }}
    .grid {{ display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:16px; margin:20px 0 28px; }}
    .card {{ background:#121a31; border:1px solid #243355; border-radius:16px; padding:18px; box-shadow:0 12px 28px rgba(0,0,0,.25); }}
    .card .label {{ color:#8ea2ca; font-size:13px; }}
    .card .value {{ font-size:30px; font-weight:700; margin-top:6px; }}
    table {{ width:100%; border-collapse: collapse; margin: 16px 0 28px; background:#121a31; border-radius:16px; overflow:hidden; }}
    th, td {{ padding: 12px 14px; border-bottom:1px solid #22304f; text-align:left; font-size:14px; vertical-align: top; }}
    th {{ background:#16203c; color:#d8e2f5; }}
    tr:last-child td {{ border-bottom:none; }}
    code {{ color:#b8d3ff; }}
    .two {{ display:grid; grid-template-columns: 1.15fr .85fr; gap:20px; }}
    .severity-group {{ background:#121a31; border:1px solid #243355; border-radius:16px; padding:16px; margin-bottom:14px; }}
    .bar-row {{ display:grid; grid-template-columns: 180px 1fr 56px; gap:12px; align-items:center; margin:10px 0; }}
    .bar-label {{ color:#dbe6ff; font-size:13px; }}
    .bar-track {{ height:12px; background:#1f2b47; border-radius:999px; overflow:hidden; }}
    .bar-fill {{ height:100%; border-radius:999px; }}
    .bar-value {{ text-align:right; color:#9fb0d1; font-size:13px; }}
    .note {{ background:#0f1730; border-left:4px solid #4aa3ff; padding:14px 16px; border-radius:10px; color:#dce7ff; }}
    ul {{ padding-left: 20px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>{project['name']} Benchmark 对比报告</h1>
    <p class="muted">GitHub：{project.get('github_url')} · 语言：{project.get('language')} · 生成口径：Fortify / 代码卫士 / IRify CLI 内存扫描</p>

    <div class="grid">
      {''.join(cards)}
    </div>

    <div class="two">
      <div>
        <h2>结论摘要</h2>
        <div class="note">
          <ul>{''.join(f'<li>{item}</li>' for item in insight_items)}</ul>
        </div>
        <h2 style="margin-top:24px;">工具对比表</h2>
        <table>
          <thead>
            <tr><th>工具</th><th>严重</th><th>高危</th><th>中危</th><th>低危</th><th>信息</th><th>耗时</th><th>样例召回</th></tr>
          </thead>
          <tbody>
            {''.join(tool_rows)}
          </tbody>
        </table>
      </div>
      <div>
        <h2>分级柱状对比</h2>
        {''.join(bars)}
      </div>
    </div>

    <h2>样例人工标注</h2>
    <table>
      <thead>
        <tr><th>case_id</th><th>规则</th><th>文件</th><th>行号</th><th>证据</th></tr>
      </thead>
      <tbody>
        {''.join(annotation_rows)}
      </tbody>
    </table>

    <h2>样例未命中概览</h2>
    <table>
      <thead>
        <tr><th>工具</th><th>未命中 case_id</th><th>数量</th></tr>
      </thead>
      <tbody>
        {''.join(unmatched_rows)}
      </tbody>
    </table>

    <h2>IRify 运行说明</h2>
    <table>
      <tbody>
        <tr><th>扫描命令</th><td><code>go run ./common/yak/cmd/yak.go code-scan --target &lt;JavaSecLab-main&gt; --language java --memory --format irify --output irify-scan.json</code></td></tr>
        <tr><th>扫描开始</th><td>{irify_result.get('summary', {}).get('scan_start_time', '')}</td></tr>
        <tr><th>扫描结束</th><td>{irify_result.get('summary', {}).get('scan_end_time', '')}</td></tr>
        <tr><th>stderr 统计</th><td>耗时 {irify_runtime.get('elapsed', '未知')}，最大内存 {irify_runtime.get('maxrss', '未知')}</td></tr>
        <tr><th>失败规则</th><td>{irify_runtime.get('failed_rule_name', '未知')}</td></tr>
      </tbody>
    </table>

    <h2>产物位置</h2>
    <ul>
      <li><code>.ai/task-runs/benchmark-framework/artifacts/javaseclab/irify-scan.json</code></li>
      <li><code>.ai/task-runs/benchmark-framework/artifacts/javaseclab/JavaSecLab-comparison-report.md</code></li>
      <li><code>.ai/task-runs/benchmark-framework/artifacts/javaseclab/JavaSecLab-comparison-report.html</code></li>
    </ul>
  </div>
</body>
</html>
"""


def top_rules(findings: list[dict[str, Any]], limit: int = 5) -> str:
    counter = Counter(finding.get("rule_type", "Unknown") for finding in findings)
    return ", ".join(f"{rule}({count})" for rule, count in counter.most_common(limit))


def match_row(label: str, result: dict[str, Any]) -> str:
    recall = result.get("sample_recall")
    recall_text = "-" if recall is None else f"{recall * 100:.1f}%"
    return f"| {label} | {result['annotations']} | {result['tp']} | {result['fn']} | {recall_text} | {result['unreviewed_findings']} |"


def stat_card(label: str, value: str) -> str:
    return f"<div class='card'><div class='label'>{label}</div><div class='value'>{value}</div></div>"


def percent(value: float | None) -> str:
    if value is None:
        return "未知"
    return f"{value * 100:.1f}%"
