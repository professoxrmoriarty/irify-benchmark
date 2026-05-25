from __future__ import annotations

import subprocess
from pathlib import Path


def build_yaklang_scan_command(
    engine: Path,
    source_dir: Path,
    output: Path,
    config: Path | None = None,
    language: str | None = None,
    report_format: str = "irify",
    memory: bool = True,
) -> list[str]:
    command = [str(engine), "code-scan", "--output", str(output), "--format", report_format]
    if config:
        command.extend(["--config", str(config)])
    else:
        command.extend(["--target", str(source_dir)])
    if language:
        command.extend(["--language", language])
    if memory:
        command.append("--memory")
    return command


def run_yaklang_scan(
    engine: Path,
    source_dir: Path,
    output: Path,
    config: Path | None = None,
    language: str | None = None,
    report_format: str = "irify",
    dry_run: bool = False,
) -> dict[str, object]:
    command = build_yaklang_scan_command(engine, source_dir, output, config, language, report_format)
    if dry_run:
        return {"command": command, "dry_run": True}
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
