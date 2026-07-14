#!/usr/bin/env python3
"""scaffold_sf_rule.py — generate a SyntaxFlow .sf rule file skeleton.

This is a helper for the write-syntaxflow-rule skill. It removes the tedious
boilerplate of a .sf rule (the leading desc metadata block, the separator
comments, and the trailing desc test-cases block) so the author can focus on
the rule body in between.

The generated file has the shape the skill recommends:

    desc(...)          # metadata: title, type, rule_id, cwe, severity, ...

    // ======================== Rule Body ========================

    <your rule logic here>

    // ======================== Test Cases ========================

    desc(...)          # trailing test block: alert_min, file://bad, safefile://good

Usage:
    python scaffold_sf_rule.py --title "Detect Java SQL Injection" \\
        --type vuln --cwe CWE-89 --severity high --language java \\
        --rule-id b8ede24d-8ff0-4d81-ab97-903495a6cb61 \\
        --output path/to/rule.sf

    # Add test cases later:
    python scaffold_sf_rule.py --append-tests path/to/rule.sf \\
        --alert-min 4 --bad-file bad.java --good-file safe.java

The script is intentionally dependency-free (stdlib only) so it runs anywhere.
"""
import argparse
import os
import sys
import uuid

RULE_BODY_SEPARATOR = "// ======================== Rule Body ========================"
TEST_SEPARATOR = "// ======================== Test Cases ========================"

# --- metadata block ---------------------------------------------------------


def build_metadata_desc(args) -> str:
    """Build the leading desc(...) metadata block."""
    lines = ["desc("]
    lines.append(f'\ttitle: "{args.title}"')
    if args.title_zh:
        lines.append(f'\ttitle_zh: "{args.title_zh}"')
    lines.append(f'\ttype: {args.type}')
    lines.append(f'\trisk: "{args.risk or args.title}"')
    rid = args.rule_id or str(uuid.uuid4())
    lines.append(f'\trule_id: "{rid}"')
    if args.cwe:
        lines.append(f'\tcwe: ["{args.cwe}"]')
    lines.append(f'\tseverity: {args.severity}')
    if args.language:
        lines.append(f'\tlanguage: {args.language}')
    if args.description:
        lines.append(f'\tdescription: <<<DESCRIPTION\n{args.description}\nDESCRIPTION')
    lines.append(")")
    return "\n".join(lines)


# --- test-cases block -------------------------------------------------------


def build_test_desc(args) -> str:
    """Build the trailing desc(...) test-cases block.

    The test block uses file:// for positive (should-alert) samples and
    safefile:// for negative (should-NOT-alert) samples, plus alert_min to
    assert a minimum alert count. yak sf-evaluate / TestVerifiedRule consume
    this block.
    """
    lines = ["desc("]
    if args.language:
        lines.append(f'\tlanguage: {args.language}')
    lines.append(f'\talert_min: {args.alert_min}')
    for i, bad in enumerate(args.bad_file or []):
        label = f'bad{i}.java' if args.language == 'java' else f'bad{i}'
        lines.append(f"\t'file://{label}': <<<FILE")
        lines.append(_read_or_placeholder(bad, args.language))
        lines.append("FILE")
    for i, good in enumerate(args.good_file or []):
        label = f'safe{i}.java' if args.language == 'java' else f'safe{i}'
        lines.append(f"\t'safefile://{label}': <<<CODE")
        lines.append(_read_or_placeholder(good, args.language))
        lines.append("CODE")
    lines.append(")")
    return "\n".join(lines)


def _read_or_placeholder(path: str, language: str) -> str:
    """Read a sample file if it exists, else emit a TODO placeholder."""
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read().rstrip()
    ext = "java" if language == "java" else "txt"
    return f"// TODO: paste a {language or 'target'} sample here (or pass --bad-file FILEPATH)"


# --- assembly ---------------------------------------------------------------


def assemble_rule(args) -> str:
    meta = build_metadata_desc(args)
    body = args.body or "// TODO: write the rule logic (source -> sink -> taint propagation -> alert)"
    test = build_test_desc(args)
    return f"{meta}\n\n\n{RULE_BODY_SEPARATOR}\n\n{body}\n\n{TEST_SEPARATOR}\n\n{test}\n"


def append_tests(path: str, args) -> None:
    """Append or replace the trailing test-cases block in an existing .sf file."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    test_block = build_test_desc(args)
    if TEST_SEPARATOR in content:
        # Replace everything from the test separator onward.
        head = content.split(TEST_SEPARATOR)[0].rstrip()
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"{head}\n\n{TEST_SEPARATOR}\n\n{test_block}\n")
    else:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"\n\n{TEST_SEPARATOR}\n\n{test_block}\n")
    print(f"appended test cases to {path}")


# --- CLI --------------------------------------------------------------------


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Scaffold a SyntaxFlow .sf rule file (metadata + body + test cases)."
    )
    p.add_argument("--title", help="rule title (English)")
    p.add_argument("--title-zh", help="rule title (Chinese, optional)")
    p.add_argument("--type", default="vuln", choices=["vuln", "audit", "sec-config"],
                   help="rule type (default: vuln)")
    p.add_argument("--risk", help="risk label (defaults to title)")
    p.add_argument("--rule-id", help="rule UUID (auto-generated if omitted)")
    p.add_argument("--cwe", help="CWE id, e.g. CWE-89")
    p.add_argument("--severity", default="mid",
                   choices=["info", "low", "mid", "middle", "high", "critical"],
                   help="severity (default: mid)")
    p.add_argument("--language", help="target language (java, go, php, ...)")
    p.add_argument("--description", help="long-form description text")
    p.add_argument("--body", help="inline rule body text (else a TODO placeholder)")
    p.add_argument("--output", "-o", help="output .sf file path")
    p.add_argument("--append-tests", metavar="SF_FILE",
                   help="append/replace test-cases block in an existing .sf file instead of creating a new one")
    p.add_argument("--alert-min", type=int, default=1, help="minimum expected alerts in test block")
    p.add_argument("--bad-file", action="append", help="positive sample file (should alert); repeatable")
    p.add_argument("--good-file", action="append", help="negative sample file (should NOT alert); repeatable")
    args = p.parse_args(argv)

    if args.append_tests:
        append_tests(args.append_tests, args)
        return 0

    if not args.title:
        p.error("--title is required when creating a new rule (or use --append-tests)")
    if not args.output:
        p.error("--output is required when creating a new rule")

    rule = assemble_rule(args)
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(rule)
    print(f"created {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())