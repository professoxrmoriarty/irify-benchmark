from __future__ import annotations

import json
import os
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from .frontend_dataset import export_frontend_dataset
from .utils import ensure_dir, read_json, read_yaml, write_json, write_yaml


def batch_build_open_source_java_projects(repo_root: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = read_yaml(manifest_path)
    projects = [item for item in manifest.get("projects", []) if str(item.get("language", "")).lower() == "java"]
    results = []
    for project in projects:
        results.append(process_java_project(repo_root, project))
    index = build_frontend_index(repo_root, results)
    write_json(repo_root / "irify-benchmark/frontend/public/data/index.json", index)
    return {"projects": results, "index": index}


def process_java_project(repo_root: Path, project: dict[str, Any]) -> dict[str, Any]:
    project_id = project["id"]
    project_name = project["name"]
    project_root = repo_root / f".ai/task-runs/benchmark-framework/projects/{project_id}"
    artifact_dir = ensure_dir(project_root / "artifacts")
    log_dir = ensure_dir(project_root / "logs")
    tmp_dir = ensure_dir(project_root / "tmp")
    source_root = ensure_project_source(repo_root, Path(project["source_package"]), tmp_dir / "source")
    readme_path = discover_readme(source_root)

    review_path, truth_path = annotation_paths(repo_root, project)
    ensure_review_file(review_path, project_name)

    irify_scan_path = artifact_dir / "irify-scan.json"
    if not irify_scan_path.exists():
        run_irify_scan(repo_root, source_root, irify_scan_path, log_dir)

    irify_findings = artifact_dir / "irify-findings.json"
    parse_report(repo_root, "irify", irify_scan_path, irify_findings, project_name)

    fortify_input = repo_root / project["reports"]["fortify"] if project.get("reports", {}).get("fortify") else None
    code_guard_input = repo_root / project["reports"]["code_guard"] if project.get("reports", {}).get("code_guard") else None
    fortify_findings = artifact_dir / "fortify-findings.json"
    code_guard_findings = artifact_dir / "code-guard-findings.json"
    if fortify_input:
        parse_report(repo_root, "fortify", fortify_input, fortify_findings, project_name)
    if code_guard_input:
        parse_report(repo_root, "code_guard", code_guard_input, code_guard_findings, project_name)

    truth_eval = artifact_dir / "truth-evaluation.json"
    truth_html = artifact_dir / "truth-report.html"
    scenario_out = artifact_dir / "scenarios.json"
    rule_index_out = artifact_dir / "java-rule-index.json"
    build_truth(
        repo_root=repo_root,
        project_name=project_name,
        source_root=source_root,
        readme_path=readme_path,
        review_path=review_path,
        truth_path=truth_path,
        scenario_out=scenario_out,
        rule_index_out=rule_index_out,
        evaluation_out=truth_eval,
        html_out=truth_html,
        irify_findings=irify_findings,
        fortify_findings=fortify_findings if fortify_findings.exists() else None,
        code_guard_findings=code_guard_findings if code_guard_findings.exists() else None,
    )

    for tool in ["irify", "code_guard", "fortify"]:
        export_pending_review(repo_root, truth_eval, pending_review_path(review_path, tool), tool)

    frontend_path = repo_root / f"irify-benchmark/frontend/public/data/projects/{project_id}.json"
    ensure_dir(frontend_path.parent)
    export_frontend_dataset(truth_path, truth_eval, frontend_path)

    evaluation = json.loads(truth_eval.read_text(encoding="utf-8"))
    summary = json.loads(frontend_path.read_text(encoding="utf-8"))["summary"]
    return {
        "projectId": project_id,
        "projectName": project_name,
        "language": project.get("language"),
        "sourceRoot": str(source_root.relative_to(repo_root)),
        "reviewPath": str(review_path.relative_to(repo_root)),
        "truthPath": str(truth_path.relative_to(repo_root)),
        "evaluationPath": str(truth_eval.relative_to(repo_root)),
        "htmlPath": str(truth_html.relative_to(repo_root)),
        "frontendPath": f"./data/projects/{project_id}.json",
        "summary": summary,
        "pendingReviewTotals": {tool: len(items) for tool, items in evaluation.get("pending_review_additions", {}).items()},
    }


def annotation_paths(repo_root: Path, project: dict[str, Any]) -> tuple[Path, Path]:
    if project["id"] == "05-javaseclab":
        return repo_root / "irify-benchmark/annotations/JavaSecLab.review.yaml", repo_root / "irify-benchmark/annotations/JavaSecLab.yaml"
    if project["id"] == "03-hello-java-sec":
        return repo_root / "irify-benchmark/annotations/Hello-Java-Sec.review.yaml", repo_root / "irify-benchmark/annotations/Hello-Java-Sec.yaml"
    base = ensure_dir(repo_root / "irify-benchmark/annotations/projects")
    return base / f"{project['id']}.review.yaml", base / f"{project['id']}.yaml"


def pending_review_path(review_path: Path, tool: str) -> Path:
    return review_path.with_name(review_path.stem.replace(".review", "") + f".pending-review.{tool}.yaml")


def ensure_review_file(path: Path, project_name: str) -> None:
    if path.exists():
        return
    ensure_dir(path.parent)
    write_yaml(path, {"project": project_name, "case_overrides": {}, "manual_cases": [], "suppressed_findings": []})


def ensure_project_source(repo_root: Path, source_package: Path, dest_dir: Path) -> Path:
    if dest_dir.exists() and any(dest_dir.iterdir()):
        return first_project_root(dest_dir)
    ensure_dir(dest_dir)
    with zipfile.ZipFile(repo_root / source_package) as archive:
        archive.extractall(dest_dir)
    return first_project_root(dest_dir)


def first_project_root(dest_dir: Path) -> Path:
    children = [item for item in dest_dir.iterdir()]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest_dir


def discover_readme(source_root: Path) -> Path:
    for candidate in ["README_ZH.md", "README.zh-CN.md", "README.md", "readme.md"]:
        path = source_root / candidate
        if path.exists():
            return path
    readmes = sorted(source_root.rglob("README*.md"))
    if readmes:
        return readmes[0]
    raise FileNotFoundError(f"README not found under {source_root}")


def run_irify_scan(repo_root: Path, source_root: Path, output_path: Path, log_dir: Path) -> None:
    cmd = [
        "go",
        "run",
        "./common/yak/cmd/yak.go",
        "code-scan",
        "--target",
        str(source_root),
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
    env = os.environ.copy()
    env["GOCACHE"] = "/tmp/go-build"
    env["GOMODCACHE"] = "/tmp/go-mod"
    stdout = (log_dir / "irify-scan.stdout.log").open("w", encoding="utf-8")
    stderr = (log_dir / "irify-scan.stderr.log").open("w", encoding="utf-8")
    try:
        subprocess.run(cmd, cwd=repo_root / "yaklang", env=env, check=True, stdout=stdout, stderr=stderr)
    finally:
        stdout.close()
        stderr.close()


def parse_report(repo_root: Path, kind: str, input_path: Path, output_path: Path, project_name: str) -> None:
    cmd = [
        "python3",
        "-m",
        "irify_benchmark",
        "parse-report",
        "--kind",
        kind,
        "--input",
        str(input_path),
        "--output",
        str(output_path),
        "--project",
        project_name,
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root / "irify-benchmark/src")
    subprocess.run(cmd, cwd=repo_root, env=env, check=True)


def build_truth(
    repo_root: Path,
    project_name: str,
    source_root: Path,
    readme_path: Path,
    review_path: Path,
    truth_path: Path,
    scenario_out: Path,
    rule_index_out: Path,
    evaluation_out: Path,
    html_out: Path,
    irify_findings: Path,
    fortify_findings: Path | None,
    code_guard_findings: Path | None,
) -> None:
    cmd = [
        "python3",
        "-m",
        "irify_benchmark",
        "rebuild-java-truth",
        "--project",
        project_name,
        "--source-root",
        str(source_root),
        "--readme",
        str(readme_path),
        "--rules-root",
        str(repo_root / "yaklang/common/syntaxflow/sfbuildin/buildin"),
        "--irify-findings",
        str(irify_findings),
        "--review-config",
        str(review_path),
        "--truth-out",
        str(truth_path),
        "--scenario-out",
        str(scenario_out),
        "--rule-index-out",
        str(rule_index_out),
        "--evaluation-out",
        str(evaluation_out),
        "--html-out",
        str(html_out),
    ]
    if code_guard_findings:
        cmd.extend(["--code-guard-findings", str(code_guard_findings)])
    if fortify_findings:
        cmd.extend(["--fortify-findings", str(fortify_findings)])
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root / "irify-benchmark/src")
    subprocess.run(cmd, cwd=repo_root, env=env, check=True)


def export_pending_review(repo_root: Path, evaluation_path: Path, output_path: Path, tool: str) -> None:
    cmd = [
        "python3",
        "-m",
        "irify_benchmark",
        "export-pending-review-cases",
        "--evaluation",
        str(evaluation_path),
        "--out",
        str(output_path),
        "--tool",
        tool,
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root / "irify-benchmark/src")
    subprocess.run(cmd, cwd=repo_root, env=env, check=True)


def build_frontend_index(repo_root: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "projects": results,
        "defaultProjectId": "05-javaseclab" if any(item["projectId"] == "05-javaseclab" for item in results) else (results[0]["projectId"] if results else ""),
    }


def sync_frontend_project_entry(repo_root: Path, project_id: str, frontend_dataset_path: Path) -> dict[str, Any]:
    frontend_dataset = read_json(frontend_dataset_path)
    public_root = repo_root / "irify-benchmark/frontend/public/data"
    project_path = public_root / "projects" / f"{project_id}.json"
    write_json(project_path, frontend_dataset)

    index_path = public_root / "index.json"
    if index_path.exists():
        index = read_json(index_path)
    else:
        index = {"projects": [], "defaultProjectId": project_id}

    projects = index.setdefault("projects", [])
    summary = frontend_dataset.get("summary", {})
    existing = next((item for item in projects if item.get("projectId") == project_id), None)
    if existing is None:
        existing = {
            "projectId": project_id,
            "projectName": frontend_dataset.get("project", project_id),
            "language": frontend_dataset.get("meta", {}).get("language", ""),
            "frontendPath": f"./data/projects/{project_id}.json",
        }
        projects.append(existing)

    existing["summary"] = summary
    existing["pendingReviewTotals"] = summary.get("pendingReviewTotals", {})
    existing["frontendPath"] = f"./data/projects/{project_id}.json"
    if not index.get("defaultProjectId"):
        index["defaultProjectId"] = project_id

    write_json(index_path, index)
    return {"projectPath": str(project_path), "indexPath": str(index_path), "projectId": project_id}
