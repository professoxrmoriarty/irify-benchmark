from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import (
    ensure_dir,
    extract_github_url,
    local_asset_path,
    parse_counts,
    read_csv,
    slugify,
    write_csv,
    write_json,
    write_yaml,
)


def clean_feishu_records(records_csv: Path, assets_csv: Path, assets_dir: Path, out_dir: Path) -> dict[str, Any]:
    ensure_dir(out_dir)
    records = read_csv(records_csv)
    assets = read_csv(assets_csv)
    assets_by_row: dict[int, list[dict[str, str]]] = {}
    for item in assets:
        assets_by_row.setdefault(int(item["row"]), []).append(item)

    open_projects: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []

    for row_number, row in enumerate(records, 1):
        project_name = row.get("项目名称", "").strip()
        github_url = extract_github_url(row.get("项目地址", ""))
        if not github_url:
            excluded.append(
                {
                    "row": row_number,
                    "project_name": project_name,
                    "project_url": row.get("项目地址", ""),
                    "reason": "missing_github_url",
                }
            )
            continue

        project_assets: dict[str, Any] = {}
        for item in assets_by_row.get(row_number, []):
            field = item["field"]
            local_path = local_asset_path(assets_dir, row_number, project_name, field, item["name"])
            entry = {
                "name": item["name"],
                "file_token": item["token"],
                "local_path": local_path,
            }
            project_assets.setdefault(field, []).append(entry)

        open_projects.append(
            {
                "id": f"{row_number:02d}-{slugify(project_name)}",
                "row": row_number,
                "name": project_name,
                "github_url": github_url,
                "language": row.get("代码语言", "").strip(),
                "priority": row.get("优先级", "").strip(),
                "source_package": first_local_path(project_assets, "项目源码包"),
                "reports": {
                    "fortify": first_local_path(project_assets, "fortify全量报告"),
                    "code_guard": first_local_path(project_assets, "代码卫士报告"),
                    "fortify_preview": first_local_path(project_assets, "fortify结果展示"),
                },
                "reported_counts": {
                    "fortify": parse_counts(row.get("Fortify发现漏洞数量", "")),
                    "code_guard": parse_counts(row.get("代码卫士漏洞数量", "")),
                    "irify": parse_counts(row.get("IRify发漏洞数量", "")),
                },
                "reported_time": {
                    "fortify": row.get("fortify扫描时间", ""),
                    "code_guard": row.get("代码卫士时间", ""),
                    "irify_compile": row.get("IRify编译时间", ""),
                    "irify_compile_scan": row.get("IRify编译+扫描速度", ""),
                },
                "raw": row,
                "assets": project_assets,
            }
        )

    manifest = {
        "suite": "feishu_open_source_projects",
        "source_records_csv": str(records_csv),
        "source_assets_csv": str(assets_csv),
        "assets_dir": str(assets_dir),
        "project_count": len(open_projects),
        "excluded_count": len(excluded),
        "projects": open_projects,
    }
    write_yaml(out_dir / "open_source_projects.yaml", manifest)
    write_json(out_dir / "open_source_projects.json", manifest)
    write_csv(out_dir / "excluded_projects.csv", excluded, ["row", "project_name", "project_url", "reason"])
    return manifest


def first_local_path(project_assets: dict[str, list[dict[str, str | None]]], field: str) -> str | None:
    items = project_assets.get(field) or []
    if not items:
        return None
    return items[0].get("local_path")

