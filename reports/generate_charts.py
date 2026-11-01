#!/usr/bin/env python3
"""Generate benchmark report charts (bar, radar, pie) for PDF embedding."""

import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import matplotlib.font_manager as fm

OUT = os.path.join(os.path.dirname(__file__), "charts")
os.makedirs(OUT, exist_ok=True)

# ---------- font ----------
_cjk_fonts = [
    f.name for f in fm.fontManager.ttflist
    if "CJK" in f.name or "Noto Sans" in f.name or "WenQuanYi" in f.name
    or "SimHei" in f.name or "Microsoft YaHei" in f.name
]
CJK = _cjk_fonts[0] if _cjk_fonts else "sans-serif"
plt.rcParams.update({
    "font.family": CJK,
    "axes.unicode_minus": False,
    "figure.dpi": 200,
    "savefig.dpi": 200,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.15,
})

COLORS = {
    "irify": "#2563eb",
    "codeguard": "#ef4444",
    "fortify": "#f59e0b",
}
LABELS = ["IRify SAST", "代码卫士", "Fortify SCA"]
C3 = [COLORS["irify"], COLORS["codeguard"], COLORS["fortify"]]


def save(fig, name):
    fig.savefig(os.path.join(OUT, name), transparent=False, facecolor="white")
    plt.close(fig)
    print(f"  ✓ {name}")


# ============================================================
# 1. 总体指标柱形图（4 指标 × 3 工具）
# ============================================================
def chart_overall_bar():
    metrics = ["扩展召回率", "高危告警\n准确率", "安全场景\n误报率\n(越低越好)", "严格召回率"]
    irify   = [57.41, 98.20, 1.67, 39.35]
    cg      = [49.54, 80.26, 23.33, 49.54]
    ft      = [34.72, 91.21, 6.67, 23.15]

    x = np.arange(len(metrics))
    w = 0.24
    fig, ax = plt.subplots(figsize=(10, 5))
    bars1 = ax.bar(x - w, irify, w, label=LABELS[0], color=C3[0], zorder=3)
    bars2 = ax.bar(x,     cg,    w, label=LABELS[1], color=C3[1], zorder=3)
    bars3 = ax.bar(x + w, ft,    w, label=LABELS[2], color=C3[2], zorder=3)

    for bars in [bars1, bars2, bars3]:
        for b in bars:
            h = b.get_height()
            ax.text(b.get_x() + b.get_width() / 2, h + 0.8, f"{h:.1f}%",
                    ha="center", va="bottom", fontsize=7.5, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=10)
    ax.set_ylabel("百分比 (%)", fontsize=10)
    ax.set_title("总体核心指标横向对比", fontsize=14, fontweight="bold", pad=12)
    ax.set_ylim(0, 115)
    ax.legend(loc="upper right", fontsize=9)
    ax.grid(axis="y", alpha=0.3, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    save(fig, "overall_bar.png")


# ============================================================
# 2. 雷达图 — 多维能力对比
# ============================================================
def chart_radar():
    cats = ["扩展召回率", "高危准确率", "低误报\n(100-误报率)", "ORM/框架\n注入覆盖", "多语言\n支持度"]
    N = len(cats)
    irify = [57.41, 98.20, 98.33, 80, 90]
    cg    = [49.54, 80.26, 76.67, 45, 40]
    ft    = [34.72, 91.21, 93.33, 20, 10]

    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))

    for vals, label, color in [(irify, LABELS[0], C3[0]),
                                (cg, LABELS[1], C3[1]),
                                (ft, LABELS[2], C3[2])]:
        v = vals + vals[:1]
        ax.plot(angles, v, "o-", linewidth=2, label=label, color=color, markersize=5)
        ax.fill(angles, v, alpha=0.08, color=color)

    ax.set_thetagrids(np.degrees(angles[:-1]), cats, fontsize=10)
    ax.set_ylim(0, 105)
    ax.set_yticks([20, 40, 60, 80, 100])
    ax.set_yticklabels(["20", "40", "60", "80", "100"], fontsize=7, alpha=0.5)
    ax.set_title("多维能力雷达图", fontsize=14, fontweight="bold", pad=24)
    ax.legend(loc="lower right", bbox_to_anchor=(1.25, -0.05), fontsize=9)
    save(fig, "radar.png")


# ============================================================
# 3. 分靶场扩展召回率柱形图
# ============================================================
def chart_per_range_recall():
    ranges = ["JavaSecLab\n(Java 企业级)", "Hello-Java-Sec\n(Java 基础)", "DVWA\n(PHP)"]
    irify = [52.94, 60.61, 67.74]
    cg    = [52.10, 39.39, 61.29]
    ft    = [26.89, 21.21, 93.55]

    x = np.arange(len(ranges))
    w = 0.24
    fig, ax = plt.subplots(figsize=(9, 5))
    b1 = ax.bar(x - w, irify, w, label=LABELS[0], color=C3[0], zorder=3)
    b2 = ax.bar(x,     cg,    w, label=LABELS[1], color=C3[1], zorder=3)
    b3 = ax.bar(x + w, ft,    w, label=LABELS[2], color=C3[2], zorder=3)

    for bars in [b1, b2, b3]:
        for b in bars:
            h = b.get_height()
            ax.text(b.get_x() + b.get_width() / 2, h + 0.8, f"{h:.1f}%",
                    ha="center", va="bottom", fontsize=8, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(ranges, fontsize=10)
    ax.set_ylabel("扩展召回率 (%)", fontsize=10)
    ax.set_title("分靶场扩展召回率对比", fontsize=14, fontweight="bold", pad=12)
    ax.set_ylim(0, 110)
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    save(fig, "recall_by_range.png")


# ============================================================
# 4. 告警量 vs 高危准确率 散点/气泡图
# ============================================================
def chart_alert_bubble():
    fig, ax = plt.subplots(figsize=(8, 5.5))
    data = [
        ("JavaSecLab",      502, 100.0, 1656, 77.85, 491, 100.0),
        ("Hello-Java-Sec",  306, 92.86,  574, 82.50, 192, 93.33),
        ("DVWA",            203, 100.0,  100, 88.57, 210, 86.79),
    ]
    markers = ["o", "s", "D"]
    for i, (name, ia, ip, ca, cp, fa, fp) in enumerate(data):
        mk = markers[i]
        ax.scatter(ia, ip, s=180, c=C3[0], marker=mk, zorder=5, edgecolors="white", linewidths=0.8)
        ax.scatter(ca, cp, s=180, c=C3[1], marker=mk, zorder=5, edgecolors="white", linewidths=0.8)
        ax.scatter(fa, fp, s=180, c=C3[2], marker=mk, zorder=5, edgecolors="white", linewidths=0.8)
        ax.annotate(name, (ia, ip), textcoords="offset points", xytext=(8, 6), fontsize=7, color=C3[0])

    for label, color in zip(LABELS, C3):
        ax.scatter([], [], c=color, s=80, label=label)
    for mk, name in zip(markers, ["JavaSecLab", "Hello-Java-Sec", "DVWA"]):
        ax.scatter([], [], c="gray", s=80, marker=mk, label=name)

    ax.set_xlabel("原始告警量", fontsize=10)
    ax.set_ylabel("高危告警准确率 (%)", fontsize=10)
    ax.set_title("告警量 vs 高危准确率（越右上越优）", fontsize=13, fontweight="bold", pad=12)
    ax.set_ylim(70, 105)
    ax.legend(fontsize=8, loc="lower left", ncol=2)
    ax.grid(alpha=0.25, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    save(fig, "alert_vs_accuracy.png")


# ============================================================
# 5. 安全场景误报率饼图 × 3
# ============================================================
def chart_safe_fp_pie():
    fig, axes = plt.subplots(1, 3, figsize=(12, 4))
    safe_data = [
        (LABELS[0], 1.67,  C3[0]),
        (LABELS[1], 23.33, C3[1]),
        (LABELS[2], 6.67,  C3[2]),
    ]
    for ax, (label, fp, color) in zip(axes, safe_data):
        sizes = [fp, 100 - fp]
        colors_pie = [color, "#e5e7eb"]
        wedges, _ = ax.pie(sizes, colors=colors_pie, startangle=90,
                           wedgeprops=dict(width=0.38, edgecolor="white", linewidth=2))
        ax.text(0, 0, f"{fp:.1f}%", ha="center", va="center",
                fontsize=18, fontweight="bold", color=color)
        ax.set_title(label, fontsize=11, fontweight="bold", pad=8)

    fig.suptitle("安全场景误报率（越低越好）", fontsize=14, fontweight="bold", y=1.02)
    fig.tight_layout()
    save(fig, "safe_fp_donut.png")


# ============================================================
# 6. 分漏洞类型热力 / 分组柱形图
# ============================================================
def chart_vuln_type_bar():
    types  = ["SQL Injection", "Command Execution", "路径遍历", "反序列化", "XSS", "SSRF", "模板注入", "XXE", "凭据/SCA", "重定向"]
    irify  = [73, 86, 78, 56, 35, 100, 56, 33, 80, 70]
    cg     = [50, 73, 67, 44, 42,  20,  0, 56, 60, 30]
    ft     = [47, 55, 22, 13, 15,   0,  0, 44, 44, 10]

    y = np.arange(len(types))
    h = 0.24
    fig, ax = plt.subplots(figsize=(10, 6.5))
    ax.barh(y + h, irify, h, label=LABELS[0], color=C3[0], zorder=3)
    ax.barh(y,     cg,    h, label=LABELS[1], color=C3[1], zorder=3)
    ax.barh(y - h, ft,    h, label=LABELS[2], color=C3[2], zorder=3)

    ax.set_yticks(y)
    ax.set_yticklabels(types, fontsize=10)
    ax.set_xlabel("扩展召回率 (%)", fontsize=10)
    ax.set_title("分漏洞类型扩展召回率对比", fontsize=14, fontweight="bold", pad=12)
    ax.set_xlim(0, 110)
    ax.legend(loc="lower right", fontsize=9)
    ax.grid(axis="x", alpha=0.3, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.invert_yaxis()
    save(fig, "vuln_type_bar.png")


# ============================================================
# 7. 运营成本对比 — 堆叠柱形图
# ============================================================
def chart_ops_cost():
    ranges = ["JavaSecLab", "Hello-Java-Sec", "DVWA"]
    irify_valid = [95, 45, 22]
    irify_noise = [13,  7,  3]
    cg_valid    = [123, 32, 30]
    cg_noise    = [35, 10,  5]
    ft_valid    = [40, 14, 38]
    ft_noise    = [5,   1,  7]

    x = np.arange(len(ranges))
    w = 0.24
    fig, ax = plt.subplots(figsize=(9, 5))

    ax.bar(x - w, irify_valid, w, label="IRify 有效告警", color=C3[0], zorder=3)
    ax.bar(x - w, irify_noise, w, bottom=irify_valid, color=C3[0], alpha=0.3, zorder=3, hatch="//")

    ax.bar(x,     cg_valid, w, label="代码卫士 有效告警", color=C3[1], zorder=3)
    ax.bar(x,     cg_noise, w, bottom=cg_valid, color=C3[1], alpha=0.3, zorder=3, hatch="//")

    ax.bar(x + w, ft_valid, w, label="Fortify 有效告警", color=C3[2], zorder=3)
    ax.bar(x + w, ft_noise, w, bottom=ft_valid, color=C3[2], alpha=0.3, zorder=3, hatch="//")

    ax.set_xticks(x)
    ax.set_xticklabels(ranges, fontsize=10)
    ax.set_ylabel("已审告警数", fontsize=10)
    ax.set_title("已审告警构成（实色=有效 / 斜线=噪声）", fontsize=13, fontweight="bold", pad=12)
    ax.legend(fontsize=8, ncol=3, loc="upper left")
    ax.grid(axis="y", alpha=0.3, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    save(fig, "ops_cost_stacked.png")


if __name__ == "__main__":
    print("Generating benchmark report charts …")
    chart_overall_bar()
    chart_radar()
    chart_per_range_recall()
    chart_alert_bubble()
    chart_safe_fp_pie()
    chart_vuln_type_bar()
    chart_ops_cost()
    print("Done — all charts saved to", OUT)
