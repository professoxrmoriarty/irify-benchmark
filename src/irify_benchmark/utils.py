from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

import yaml


SEVERITY_ALIASES = {
    "严重": "critical",
    "Critical": "critical",
    "critical": "critical",
    "高危": "high",
    "High": "high",
    "high": "high",
    "中危": "medium",
    "Medium": "medium",
    "medium": "medium",
    "低危": "low",
    "Low": "low",
    "low": "low",
    "信息": "info",
    "Info": "info",
    "info": "info",
}


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def read_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def write_yaml(path: Path, data: Any) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, allow_unicode=True, sort_keys=False)


def write_json(path: Path, data: Any) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"https?://", "", value)
    value = re.sub(r"[^a-z0-9\u4e00-\u9fff._+-]+", "-", value)
    return value.strip("-") or "item"


def sanitize_filename(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", str(name)).strip().strip(".")
    name = re.sub(r"\s+", " ", name)
    return name[:180] or "asset"


def extract_github_url(value: str) -> str | None:
    if not value:
        return None
    match = re.search(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value)
    return match.group(0) if match else None


def parse_counts(value: str) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if not value:
        return counts
    for label, number in re.findall(r"(严重|高危|中危|低危|信息|Critical|High|Medium|Low|Info)\s*([0-9,]+)\s*个?", value):
        counts[SEVERITY_ALIASES[label]] += int(number.replace(",", ""))
    return counts


def normalize_path(value: str) -> str:
    value = str(value or "").replace("\\", "/")
    value = re.sub(r"^.*?(JavaSecLab-main|Hello-Java-Sec-master|micro_service_seclab-main|WebBug-master|WebGoat-main|nginxWebUI-4\.2\.9|svnWebUI-1\.8\.9|warehouse-master|carRental-master|java-sec-code-master|DVWA-2\.5|sonic-server-main)/", "", value)
    value = re.sub(r"^.*?/(?=src/)", "", value)
    return value.lstrip("./")


def path_matches(left: str, right: str) -> bool:
    left_norm = normalize_path(left).lower()
    right_norm = normalize_path(right).lower()
    return left_norm == right_norm or left_norm.endswith(right_norm) or right_norm.endswith(left_norm)


def local_asset_path(assets_dir: Path, row_number: int, project: str, field: str, name: str) -> str | None:
    prefix = f"{row_number:02d}-{sanitize_filename(project)}-{sanitize_filename(field)}-{sanitize_filename(name)}"
    matches = sorted(assets_dir.glob(prefix + "*"))
    if not matches:
        return None
    return str(matches[0])
