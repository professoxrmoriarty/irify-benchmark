from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def create_feishu_doc(
    markdown_path: Path,
    title: str,
    wiki_node: str | None = None,
    wiki_space: str | None = None,
    folder_token: str | None = None,
    identity: str = "bot",
    dry_run: bool = True,
) -> dict[str, Any]:
    lark_cli = shutil.which("lark-cli") or "/home/zpy/.npm-global/bin/lark-cli"
    markdown = markdown_path.read_text(encoding="utf-8")
    command = [lark_cli, "docs", "+create", "--as", identity, "--title", title, "--markdown", markdown]
    if wiki_node:
        command.extend(["--wiki-node", wiki_node])
    elif wiki_space:
        command.extend(["--wiki-space", wiki_space])
    elif folder_token:
        command.extend(["--folder-token", folder_token])
    if dry_run:
        return {"dry_run": True, "command": redact_long_markdown(command)}
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    result: dict[str, Any] = {
        "dry_run": False,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    try:
        result["json"] = json.loads(completed.stdout)
    except json.JSONDecodeError:
        pass
    return result


def redact_long_markdown(command: list[str]) -> list[str]:
    redacted = list(command)
    if "--markdown" in redacted:
        index = redacted.index("--markdown")
        if index + 1 < len(redacted):
            redacted[index + 1] = f"<markdown {len(redacted[index + 1])} chars>"
    return redacted

