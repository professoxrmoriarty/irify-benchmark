from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .utils import write_json, write_yaml


def index_java_rules(rules_root: Path) -> dict[str, Any]:
    rules = []
    java_root = rules_root / "java"
    for path in sorted(java_root.rglob("*.sf")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        relative_path = str(path.relative_to(rules_root))
        title_zh = find_field(text, "title_zh")
        title = find_field(text, "title")
        risk = find_field(text, "risk")
        rule_id = find_field(text, "rule_id")
        rules.append(
            {
                "relative_path": relative_path,
                "title_zh": title_zh,
                "title": title,
                "risk": risk,
                "rule_id": rule_id,
                "search_text": " ".join([relative_path, title_zh, title, risk]).lower(),
            }
        )
    return {
        "language": "java",
        "rules_root": str(rules_root),
        "rule_count": len(rules),
        "rules": rules,
    }


def find_field(text: str, field: str) -> str:
    match = re.search(rf"{field}\s*:\s*\"([^\"]+)\"", text)
    return match.group(1) if match else ""


def export_rule_index(path: Path, data: dict[str, Any]) -> None:
    if path.suffix in {".yaml", ".yml"}:
        write_yaml(path, data)
    else:
        write_json(path, data)

