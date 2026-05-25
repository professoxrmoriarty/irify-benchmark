from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import read_yaml


def render_truth_html(truth_path: Path, evaluation: dict[str, Any], output: Path) -> str:
    truth = read_yaml(truth_path)
    cases = truth.get("cases", [])
    project_name = truth.get("project", "Benchmark")
    by_tool = evaluation["overall"]
    pending_policy = evaluation.get("pending_review_policy", {}) or {}
    cards = [
        card("总场景", str(len(cases))),
        card("漏洞正例", str(sum(1 for item in cases if item.get("expectation") == "must_alert"))),
        card("应降级提示", str(sum(1 for item in cases if item.get("expectation") == "should_warn"))),
        card("安全负例", str(sum(1 for item in cases if item.get("expectation") == "must_not_alert"))),
        card("IRify 规则覆盖", str(sum(1 for item in cases if item.get("irify_support") == "supported"))),
    ]
    metric_bars = []
    for label, key, color in [("Fortify", "fortify", "#d17d43"), ("代码卫士", "code_guard", "#4aa3ff"), ("IRify", "irify", "#57c27d")]:
        stat = by_tool[key]
        policy = (pending_policy.get("tools", {}) or {}).get(key, {}) or {}
        recall = 0 if stat["positive_recall"] is None else int(stat["positive_recall"] * 100)
        relaxed_recall = 0 if stat["positive_relaxed_recall"] is None else int(stat["positive_relaxed_recall"] * 100)
        noise_rate = 0 if stat["finding_noise_rate"] is None else int(stat["finding_noise_rate"] * 100)
        high_overreport = 0 if stat["high_risk_overreport_rate"] is None else int(stat["high_risk_overreport_rate"] * 100)
        pending_rate = 0 if stat["finding_pending_rate"] is None else int(stat["finding_pending_rate"] * 100)
        metric_bars.append(
            f"<div class='metric-card'><h3>{label}</h3>"
            f"<div class='metric-row'><span>严格召回</span><div class='track'><div class='fill' style='width:{recall}%;background:{color}'></div></div><strong>{format_percent(stat['positive_recall'])}</strong></div>"
            f"<div class='metric-row'><span>扩展召回</span><div class='track'><div class='fill' style='width:{relaxed_recall}%;background:{color}'></div></div><strong>{format_percent(stat['positive_relaxed_recall'])}</strong></div>"
            f"<div class='metric-row'><span>已审噪声</span><div class='track'><div class='fill' style='width:{noise_rate}%;background:#d1b243'></div></div><strong>{formatPercentText(stat['finding_noise_total'], stat['finding_noise_rate'])}</strong></div>"
            f"<div class='metric-row'><span>高危过报</span><div class='track'><div class='fill' style='width:{high_overreport}%;background:#d14343'></div></div><strong>{formatPercentText(stat['high_risk_confirmed_false_positive'] + stat['high_risk_overstated'], stat['high_risk_overreport_rate'])}</strong></div>"
            f"<div class='metric-row'><span>待复核</span><div class='track'><div class='fill' style='width:{pending_rate}%;background:#7d8ca3'></div></div><strong>{stat['finding_pending_review']} / raw {int(policy.get('raw_total', stat['finding_pending_review']))}</strong></div>"
            "</div>"
        )
    tool_rows = []
    for label, key in [("Fortify", "fortify"), ("代码卫士", "code_guard"), ("IRify", "irify")]:
        stat = by_tool[key]
        policy = (pending_policy.get("tools", {}) or {}).get(key, {}) or {}
        tool_rows.append(
            "<tr>"
            f"<td>{label}</td>"
            f"<td>{stat['positive_total']}</td>"
            f"<td>{stat['positive_supported']}</td>"
            f"<td>{stat['positive_tp']}</td>"
            f"<td>{stat['positive_relaxed_tp']}</td>"
            f"<td>{stat['positive_fn']}</td>"
            f"<td>{format_percent(stat['positive_recall'])}</td>"
            f"<td>{format_percent(stat['positive_relaxed_recall'])}</td>"
            f"<td>{stat['warn_supported']}</td>"
            f"<td>{stat['warn_matched']}</td>"
            f"<td>{stat['warn_overstated']}</td>"
            f"<td>{stat['safe_supported']}</td>"
            f"<td>{stat['safe_severe_fp']}</td>"
            f"<td>{format_percent(stat['safe_fp_rate'])}</td>"
            f"<td>{stat['safe_advisory_noise']}</td>"
            f"<td>{format_percent(stat['safe_advisory_rate'])}</td>"
            f"<td>{stat['finding_useful_alerts']}</td>"
            f"<td>{stat['finding_noise_total']}</td>"
            f"<td>{format_percent(stat['finding_noise_rate'])}</td>"
            f"<td>{stat['finding_pending_review']} / raw {int(policy.get('raw_total', stat['finding_pending_review']))}</td>"
            f"<td>{format_percent(stat['finding_pending_rate'])}</td>"
            f"<td>{format_ratio(stat['finding_audit_load'])}</td>"
            f"<td>{stat['high_risk_reviewed_total']}</td>"
            f"<td>{stat['high_risk_confirmed_false_positive']}</td>"
            f"<td>{stat['high_risk_overstated']}</td>"
            f"<td>{format_percent(stat['high_risk_false_positive_rate'])}</td>"
            f"<td>{format_percent(stat['high_risk_overreport_rate'])}</td>"
            f"<td>{stat['unsupported_cases']}</td>"
            f"<td>{stat['pending_review_additions']}</td>"
            "</tr>"
        )
    family_rows = []
    for item in evaluation["families"]:
        family_rows.append(
            "<tr>"
            f"<td>{item['family']}</td>"
            f"<td>{item['positive_cases']}</td>"
            f"<td>{item['safe_cases']}</td>"
            f"<td>{status_text(item['irify'])}</td>"
            f"<td>{status_text(item['code_guard'])}</td>"
            f"<td>{status_text(item['fortify'])}</td>"
            "</tr>"
        )
    highlight_rows = []
    for case in cases:
        if case["verification_status"].get("irify") in {"covered_missed", "severe_false_positive", "warning_overstated", "hit_downgraded", "advisory_noise"}:
            highlight_rows.append(
                "<tr>"
                f"<td>{case['case_id']}</td>"
                f"<td>{case['route']}</td>"
                f"<td>{case['rule_type']}</td>"
                f"<td>{'正例' if case['expectation']=='must_alert' else '负例'}</td>"
                f"<td>{case.get('expected_severity_band', []) or 'none'}</td>"
                f"<td>{case['verification_status'].get('irify')}</td>"
                f"<td><code>{case['canonical_file_path']}:{case['line_start']}</code></td>"
                f"<td>{'; '.join(case.get('notes', []))}</td>"
                "</tr>"
            )
    pending_rows = []
    pending = evaluation.get("pending_review_additions", {})
    for label, key in [("Fortify", "fortify"), ("代码卫士", "code_guard"), ("IRify", "irify")]:
        for item in pending.get(key, [])[:40]:
            pending_rows.append(
                "<tr>"
                f"<td>{label}</td>"
                f"<td>{item.get('rule_name')}</td>"
                f"<td>{item.get('severity')}</td>"
                f"<td><code>{item.get('file_path')}:{item.get('line_start')}</code></td>"
                f"<td>{', '.join(item.get('candidate_case_ids', [])) or '-'}</td>"
                f"<td>{item.get('evidence', '')}</td>"
                "</tr>"
            )
    sample_rows = []
    for case in cases[:30]:
        sink = case.get("sink") or {}
        sample_rows.append(
            "<tr>"
            f"<td>{case['case_id']}</td>"
            f"<td>{case['route']}</td>"
            f"<td>{case['rule_type']}</td>"
            f"<td>{case['expectation']}</td>"
            f"<td>{case.get('expected_severity_band', []) or 'none'}</td>"
            f"<td>{case['source']['notes']}</td>"
            f"<td>{sink.get('api', '-')[:120]}</td>"
            f"<td>{case['verification_status'].get('irify')}</td>"
            "</tr>"
        )
    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>{project_name} 全量真值评估报告</title>
  <style>
    body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#0b1020; color:#e8edf7; margin:0; }}
    .wrap {{ max-width: 1380px; margin:0 auto; padding:32px; }}
    .grid {{ display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:16px; margin:20px 0 28px; }}
    .card {{ background:#121a31; border:1px solid #243355; border-radius:16px; padding:18px; }}
    .label {{ color:#8ea2ca; font-size:13px; }}
    .value {{ font-size:28px; font-weight:700; margin-top:6px; }}
    table {{ width:100%; border-collapse:collapse; margin:16px 0 28px; background:#121a31; }}
    th,td {{ padding:12px 14px; border-bottom:1px solid #22304f; text-align:left; vertical-align:top; font-size:14px; }}
    th {{ background:#16203c; }}
    tr:last-child td {{ border-bottom:none; }}
    .note {{ background:#0f1730; border-left:4px solid #4aa3ff; padding:14px 16px; border-radius:10px; }}
    code {{ color:#b8d3ff; }}
    .metrics {{ display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:16px; margin:16px 0 28px; }}
    .metric-card {{ background:#121a31; border:1px solid #243355; border-radius:16px; padding:16px; }}
    .metric-row {{ display:grid; grid-template-columns: 92px 1fr 64px; gap:10px; align-items:center; margin:10px 0; }}
    .track {{ height:12px; background:#1f2b47; border-radius:999px; overflow:hidden; }}
    .fill {{ height:100%; border-radius:999px; }}
  </style>
</head>
<body>
<div class="wrap">
  <h1>{project_name} 全量真值评估报告</h1>
  <p>口径：以源码场景为主、以 IRify `sfbuildin` Java 内置规则映射为辅，对 Fortify / 代码卫士 / IRify 进行统一评估。</p>
  <div class="grid">{''.join(cards)}</div>
  <div class="note">
    <ul>
      <li>当前真值集覆盖 `vul` 正例和 `safe` 负例两类场景，重复源码副本不重复计数。</li>
      <li>支持规则映射的场景才进入统计；未映射场景单独列为 `unsupported`。</li>
      <li>评估分三层：发现能力（召回）、审计负担（有多少噪声和待复核）、分级质量（高危/严重是否乱报）。</li>
      <li>IRify 规则支持按消毒/过滤路径降级，因此 safe 命中会拆成“严重误报”与“降级提示”；`should_warn` 场景会额外统计“高危过报”。</li>
      <li>待复核分 raw 与 kept 两层：raw 是工具原始额外告警，kept 是当前保留给人工复核队列的高信号项。</li>
    </ul>
  </div>
  <h2>核心指标可视化</h2>
  <div class="metrics">{''.join(metric_bars)}</div>
  <h2>工具总览</h2>
  <table>
    <thead><tr><th>工具</th><th>正例总数</th><th>正例可评估</th><th>严格TP</th><th>扩展TP</th><th>FN</th><th>严格召回</th><th>扩展召回</th><th>降级提示场景</th><th>命中降级提示</th><th>等级过高</th><th>safe 可评估</th><th>严重误报</th><th>严重误报率</th><th>降级提示</th><th>降级提示率</th><th>有效告警</th><th>已审噪声</th><th>已审噪声率</th><th>待复核 kept/raw</th><th>待复核率</th><th>每真信号审查量</th><th>高危已审</th><th>高危误报</th><th>高危过报</th><th>高危误报率</th><th>高危过报率</th><th>未映射场景</th><th>待复核新增项</th></tr></thead>
    <tbody>{''.join(tool_rows)}</tbody>
  </table>
  <h2>漏洞家族矩阵</h2>
  <table>
    <thead><tr><th>家族</th><th>正例</th><th>负例</th><th>IRify</th><th>代码卫士</th><th>Fortify</th></tr></thead>
    <tbody>{''.join(family_rows)}</tbody>
  </table>
  <h2>IRify 重点未命中/误报</h2>
  <table>
    <thead><tr><th>case_id</th><th>路由</th><th>规则类型</th><th>场景类型</th><th>预期等级带</th><th>IRify 状态</th><th>位置</th><th>说明</th></tr></thead>
    <tbody>{''.join(highlight_rows) or '<tr><td colspan=\"7\">无</td></tr>'}</tbody>
  </table>
  <h2>待复核新增项</h2>
  <table>
    <thead><tr><th>工具</th><th>规则</th><th>级别</th><th>位置</th><th>候选 case</th><th>说明</th></tr></thead>
    <tbody>{''.join(pending_rows) or '<tr><td colspan=\"6\">无</td></tr>'}</tbody>
  </table>
  <h2>样例场景明细（前 30 条）</h2>
  <table>
    <thead><tr><th>case_id</th><th>route</th><th>rule_type</th><th>expectation</th><th>预期等级带</th><th>source</th><th>sink</th><th>IRify</th></tr></thead>
    <tbody>{''.join(sample_rows)}</tbody>
  </table>
</div>
</body>
</html>
"""
    output.write_text(html, encoding="utf-8")
    return html


def card(label: str, value: str) -> str:
    return f"<div class='card'><div class='label'>{label}</div><div class='value'>{value}</div></div>"


def format_percent(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.1f}%"


def formatPercentText(count: int, value: float | None) -> str:
    if value is None:
        return str(count)
    return f"{count} / {value * 100:.1f}%"


def format_ratio(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}"


def status_text(counter: dict[str, int]) -> str:
    interesting = [f"{key}:{value}" for key, value in counter.items() if value]
    return ", ".join(interesting) or "-"
