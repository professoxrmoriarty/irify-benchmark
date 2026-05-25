from __future__ import annotations

import argparse
from pathlib import Path

from .batch_java_projects import batch_build_open_source_java_projects, sync_frontend_project_entry
from .feishu_clean import clean_feishu_records
from .frontend_dataset import export_frontend_dataset
from .matcher import write_match_report
from .owasp_benchmark import run_owasp_benchmark
from .pending_review_cases import export_pending_review_cases
from .parsers import parse_code_guard_docx, parse_fortify_pdf, parse_irify_json
from .publishers import create_feishu_doc
from .report import generate_project_report, generate_project_html_report, find_project
from .rule_index import export_rule_index, index_java_rules
from .scenario_discovery import discover_java_scenarios
from .truth_builder import build_javaseclab_truth, build_manual_truth, export_truth
from .truth_builder import build_java_truth
from .truth_eval import evaluate_truth, export_evaluation
from .truth_report import render_truth_html
from .utils import ensure_dir, read_json, read_yaml, write_json


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="irify-benchmark")
    subparsers = parser.add_subparsers(dest="command", required=True)

    clean = subparsers.add_parser("clean-feishu")
    clean.add_argument("--records-csv", type=Path, required=True)
    clean.add_argument("--assets-csv", type=Path, required=True)
    clean.add_argument("--assets-dir", type=Path, required=True)
    clean.add_argument("--out-dir", type=Path, required=True)

    parse_report = subparsers.add_parser("parse-report")
    parse_report.add_argument("--kind", choices=["fortify", "code_guard", "irify"], required=True)
    parse_report.add_argument("--input", type=Path, required=True)
    parse_report.add_argument("--output", type=Path, required=True)
    parse_report.add_argument("--project", default="")

    match = subparsers.add_parser("match")
    match.add_argument("--annotations", type=Path, required=True)
    match.add_argument("--findings", type=Path, required=True)
    match.add_argument("--output", type=Path, required=True)
    match.add_argument("--line-window", type=int, default=3)

    sample = subparsers.add_parser("sample-javaseclab")
    sample.add_argument("--manifest", type=Path, required=True)
    sample.add_argument("--annotations", type=Path, required=True)
    sample.add_argument("--out-dir", type=Path, required=True)

    publish = subparsers.add_parser("publish-feishu")
    publish.add_argument("--markdown", type=Path, required=True)
    publish.add_argument("--title", required=True)
    publish.add_argument("--wiki-node")
    publish.add_argument("--wiki-space")
    publish.add_argument("--folder-token")
    publish.add_argument("--as", dest="identity", default="bot", choices=["bot", "user"])
    publish.add_argument("--execute", action="store_true")

    html = subparsers.add_parser("build-html-report")
    html.add_argument("--manifest", type=Path, required=True)
    html.add_argument("--project", required=True)
    html.add_argument("--annotations", type=Path, required=True)
    html.add_argument("--fortify", type=Path, required=True)
    html.add_argument("--code-guard", type=Path, required=True)
    html.add_argument("--irify", type=Path, required=True)
    html.add_argument("--out", type=Path, required=True)
    html.add_argument("--irify-runtime", type=Path)

    discover = subparsers.add_parser("discover-scenarios")
    discover.add_argument("--source-root", type=Path, required=True)
    discover.add_argument("--readme", type=Path)
    discover.add_argument("--out", type=Path, required=True)

    rules = subparsers.add_parser("index-rules")
    rules.add_argument("--rules-root", type=Path, required=True)
    rules.add_argument("--out", type=Path, required=True)

    truth = subparsers.add_parser("rebuild-javaseclab-truth")
    truth.add_argument("--source-root", type=Path, required=True)
    truth.add_argument("--readme", type=Path, required=True)
    truth.add_argument("--rules-root", type=Path, required=True)
    truth.add_argument("--irify-findings", type=Path, required=True)
    truth.add_argument("--code-guard-findings", type=Path, required=True)
    truth.add_argument("--fortify-findings", type=Path, required=True)
    truth.add_argument("--truth-out", type=Path, required=True)
    truth.add_argument("--scenario-out", type=Path)
    truth.add_argument("--rule-index-out", type=Path)
    truth.add_argument("--evaluation-out", type=Path)
    truth.add_argument("--html-out", type=Path)

    manual_truth = subparsers.add_parser("rebuild-manual-truth")
    manual_truth.add_argument("--project", required=True)
    manual_truth.add_argument("--review-config", type=Path, required=True)
    manual_truth.add_argument("--irify-findings", type=Path, required=True)
    manual_truth.add_argument("--code-guard-findings", type=Path)
    manual_truth.add_argument("--fortify-findings", type=Path)
    manual_truth.add_argument("--source-root", type=Path)
    manual_truth.add_argument("--language", default="")
    manual_truth.add_argument("--truth-out", type=Path, required=True)
    manual_truth.add_argument("--evaluation-out", type=Path)
    manual_truth.add_argument("--html-out", type=Path)

    generic_truth = subparsers.add_parser("rebuild-java-truth")
    generic_truth.add_argument("--project", required=True)
    generic_truth.add_argument("--source-root", type=Path, required=True)
    generic_truth.add_argument("--readme", type=Path, required=True)
    generic_truth.add_argument("--rules-root", type=Path, required=True)
    generic_truth.add_argument("--irify-findings", type=Path, required=True)
    generic_truth.add_argument("--code-guard-findings", type=Path)
    generic_truth.add_argument("--fortify-findings", type=Path)
    generic_truth.add_argument("--review-config", type=Path)
    generic_truth.add_argument("--truth-out", type=Path, required=True)
    generic_truth.add_argument("--scenario-out", type=Path)
    generic_truth.add_argument("--rule-index-out", type=Path)
    generic_truth.add_argument("--evaluation-out", type=Path)
    generic_truth.add_argument("--html-out", type=Path)

    frontend = subparsers.add_parser("export-frontend-data")
    frontend.add_argument("--truth", type=Path, required=True)
    frontend.add_argument("--evaluation", type=Path, required=True)
    frontend.add_argument("--out", type=Path, required=True)

    pending_cases = subparsers.add_parser("export-pending-review-cases")
    pending_cases.add_argument("--evaluation", type=Path, required=True)
    pending_cases.add_argument("--out", type=Path, required=True)
    pending_cases.add_argument("--tool", default="irify", choices=["irify", "code_guard", "fortify"])

    owasp = subparsers.add_parser("run-owasp-benchmark")
    owasp.add_argument("--benchmark-root", type=Path, required=True)
    owasp.add_argument("--out-dir", type=Path, required=True)
    owasp.add_argument("--expected-results", type=Path)
    owasp.add_argument("--scan-json", type=Path)
    owasp.add_argument("--skip-scan", action="store_true")

    batch_java = subparsers.add_parser("batch-build-open-source-java")
    batch_java.add_argument("--repo-root", type=Path, default=Path("."))
    batch_java.add_argument("--manifest", type=Path, required=True)

    sync_frontend = subparsers.add_parser("sync-frontend-project")
    sync_frontend.add_argument("--repo-root", type=Path, default=Path("."))
    sync_frontend.add_argument("--project-id", required=True)
    sync_frontend.add_argument("--frontend-dataset", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.command == "clean-feishu":
        manifest = clean_feishu_records(args.records_csv, args.assets_csv, args.assets_dir, args.out_dir)
        print(f"open_source_projects={manifest['project_count']} excluded={manifest['excluded_count']}")
    elif args.command == "parse-report":
        result = parse_one_report(args.kind, args.input, args.project)
        write_json(args.output, result)
        print(f"{args.kind} findings={result['findings_count']} output={args.output}")
    elif args.command == "match":
        result = write_match_report(args.output, args.annotations, args.findings, args.line_window)
        print(f"tp={result['tp']} fn={result['fn']} unreviewed={result['unreviewed_findings']}")
    elif args.command == "sample-javaseclab":
        run_javaseclab_sample(args.manifest, args.annotations, args.out_dir)
    elif args.command == "publish-feishu":
        result = create_feishu_doc(
            markdown_path=args.markdown,
            title=args.title,
            wiki_node=args.wiki_node,
            wiki_space=args.wiki_space,
            folder_token=args.folder_token,
            identity=args.identity,
            dry_run=not args.execute,
        )
        print(result)
    elif args.command == "build-html-report":
        generate_project_html_report(
            manifest_path=args.manifest,
            project_name=args.project,
            annotations_path=args.annotations,
            fortify_result=read_json(args.fortify),
            code_guard_result=read_json(args.code_guard),
            irify_result=read_json(args.irify),
            out_path=args.out,
            irify_runtime=read_json(args.irify_runtime) if args.irify_runtime else None,
        )
        print(f"html={args.out}")
    elif args.command == "discover-scenarios":
        data = discover_java_scenarios(args.source_root, args.readme)
        if args.out.suffix in {".yaml", ".yml"}:
            from .utils import write_yaml

            write_yaml(args.out, data)
        else:
            write_json(args.out, data)
        print(f"scenarios={data['summary']['total_cases']} output={args.out}")
    elif args.command == "index-rules":
        data = index_java_rules(args.rules_root)
        export_rule_index(args.out, data)
        print(f"rules={data['rule_count']} output={args.out}")
    elif args.command == "rebuild-javaseclab-truth":
        ensure_dir(args.truth_out.parent)
        truth = build_javaseclab_truth(
            source_root=args.source_root,
            readme_path=args.readme,
            rules_root=args.rules_root,
            irify_findings_path=args.irify_findings,
            code_guard_findings_path=args.code_guard_findings,
            fortify_findings_path=args.fortify_findings,
        )
        export_truth(args.truth_out, truth)
        if args.scenario_out:
            data = discover_java_scenarios(args.source_root, args.readme)
            if args.scenario_out.suffix in {".yaml", ".yml"}:
                from .utils import write_yaml

                write_yaml(args.scenario_out, data)
            else:
                write_json(args.scenario_out, data)
        if args.rule_index_out:
            export_rule_index(args.rule_index_out, index_java_rules(args.rules_root))
        if args.evaluation_out or args.html_out:
            evaluation = evaluate_truth(args.truth_out)
            if args.evaluation_out:
                export_evaluation(args.evaluation_out, evaluation)
            if args.html_out:
                render_truth_html(args.truth_out, evaluation, args.html_out)
        print(f"truth={args.truth_out}")
    elif args.command == "rebuild-manual-truth":
        ensure_dir(args.truth_out.parent)
        truth = build_manual_truth(
            project_name=args.project,
            review_config_path=args.review_config,
            irify_findings_path=args.irify_findings,
            code_guard_findings_path=args.code_guard_findings,
            fortify_findings_path=args.fortify_findings,
            source_root=args.source_root,
            language=args.language,
        )
        export_truth(args.truth_out, truth)
        if args.evaluation_out or args.html_out:
            evaluation = evaluate_truth(args.truth_out)
            if args.evaluation_out:
                export_evaluation(args.evaluation_out, evaluation)
            if args.html_out:
                render_truth_html(args.truth_out, evaluation, args.html_out)
        print(f"truth={args.truth_out}")
    elif args.command == "rebuild-java-truth":
        ensure_dir(args.truth_out.parent)
        truth = build_java_truth(
            project_name=args.project,
            source_root=args.source_root,
            readme_path=args.readme,
            rules_root=args.rules_root,
            irify_findings_path=args.irify_findings,
            code_guard_findings_path=args.code_guard_findings,
            fortify_findings_path=args.fortify_findings,
            review_config_path=args.review_config,
        )
        export_truth(args.truth_out, truth)
        if args.scenario_out:
            data = discover_java_scenarios(args.source_root, args.readme)
            if args.scenario_out.suffix in {".yaml", ".yml"}:
                from .utils import write_yaml

                write_yaml(args.scenario_out, data)
            else:
                write_json(args.scenario_out, data)
        if args.rule_index_out:
            export_rule_index(args.rule_index_out, index_java_rules(args.rules_root))
        if args.evaluation_out or args.html_out:
            evaluation = evaluate_truth(args.truth_out)
            if args.evaluation_out:
                export_evaluation(args.evaluation_out, evaluation)
            if args.html_out:
                render_truth_html(args.truth_out, evaluation, args.html_out)
        print(f"truth={args.truth_out}")
    elif args.command == "export-frontend-data":
        data = export_frontend_dataset(args.truth, args.evaluation, args.out)
        print(f"frontend_cases={len(data['cases'])} output={args.out}")
    elif args.command == "export-pending-review-cases":
        data = export_pending_review_cases(args.evaluation, args.out, args.tool)
        print(f"pending_review_cases={len(data['review_cases'])} output={args.out}")
    elif args.command == "run-owasp-benchmark":
        result = run_owasp_benchmark(
            benchmark_root=args.benchmark_root,
            out_dir=args.out_dir,
            expected_results_path=args.expected_results,
            scan_json_path=args.scan_json,
            skip_scan=args.skip_scan,
        )
        print(
            "score={score} tpr={tpr} fpr={fpr} report={report}".format(
                score=result["overall_score_100"],
                tpr=result["overall_tpr"],
                fpr=result["overall_fpr"],
                report=result["report_markdown"],
            )
        )
    elif args.command == "batch-build-open-source-java":
        data = batch_build_open_source_java_projects(args.repo_root.resolve(), args.manifest)
        print(f"projects={len(data['projects'])} index={args.repo_root.resolve() / 'irify-benchmark/frontend/public/data/index.json'}")
    elif args.command == "sync-frontend-project":
        data = sync_frontend_project_entry(args.repo_root.resolve(), args.project_id, args.frontend_dataset)
        print(f"project={data['projectId']} project_json={data['projectPath']} index={data['indexPath']}")


def parse_one_report(kind: str, input_path: Path, project: str) -> dict:
    if kind == "fortify":
        return parse_fortify_pdf(input_path, project)
    if kind == "irify":
        return parse_irify_json(input_path, project)
    return parse_code_guard_docx(input_path, project)


def run_javaseclab_sample(manifest_path: Path, annotations_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = read_yaml(manifest_path)
    project = find_project(manifest, "JavaSecLab")
    fortify_path = Path(project["reports"]["fortify"])
    code_guard_path = Path(project["reports"]["code_guard"])
    fortify_result = parse_fortify_pdf(fortify_path, "JavaSecLab")
    code_guard_result = parse_code_guard_docx(code_guard_path, "JavaSecLab")
    write_json(out_dir / "fortify-findings.json", fortify_result)
    write_json(out_dir / "code-guard-findings.json", code_guard_result)
    write_match_report(out_dir / "fortify-match.json", annotations_path, out_dir / "fortify-findings.json")
    write_match_report(out_dir / "code-guard-match.json", annotations_path, out_dir / "code-guard-findings.json")
    generate_project_report(
        manifest_path=manifest_path,
        project_name="JavaSecLab",
        annotations_path=annotations_path,
        fortify_result=fortify_result,
        code_guard_result=code_guard_result,
        out_path=out_dir / "JavaSecLab-comparison-report.md",
    )
    print(f"report={out_dir / 'JavaSecLab-comparison-report.md'}")



if __name__ == "__main__":
    main()
