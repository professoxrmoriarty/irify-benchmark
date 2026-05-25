from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .truth_profiles import classify_family, get_family_profile, recommended_expectation
from .utils import normalize_path, slugify


FRAMEWORK_PARAM_TYPES = {
    "HttpServletRequest",
    "HttpServletResponse",
    "HttpSession",
    "Model",
    "ModelMap",
    "UserDetails",
    "MultipartHttpServletRequest",
    "Authentication",
}


def discover_java_scenarios(source_root: Path, readme_path: Path | None = None) -> dict[str, Any]:
    root = source_root / "src" / "main" / "java"
    controllers = sorted(path for path in root.rglob("*.java") if is_controller_like(path))
    scenarios: list[dict[str, Any]] = []
    for controller in controllers:
        scenarios.extend(parse_controller(controller, root))
    summary = {
        "controllers_with_cases": len({item["controller_path"] for item in scenarios}),
        "total_cases": len(scenarios),
        "total_vul_cases": sum(1 for item in scenarios if item["expectation"] == "must_alert"),
        "total_safe_cases": sum(1 for item in scenarios if item["expectation"] == "must_not_alert"),
    }
    return {
        "project": "JavaSecLab",
        "source_root": str(source_root),
        "readme_path": str(readme_path) if readme_path else None,
        "summary": summary,
        "scenarios": scenarios,
    }


def parse_controller(path: Path, java_root: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    class_annotations: list[str] = []
    class_route = ""
    class_tags = ""
    module = module_name_from_path(path)
    controller_name = path.name
    pending_annotations: list[str] = []
    scenarios: list[dict[str, Any]] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if stripped.startswith("@"):
            annotation_block, end_index = collect_annotation_block(lines, index)
            pending_annotations.append("\n".join(annotation_block))
            index = end_index + 1
            continue
        if " class " in stripped and stripped.endswith("{"):
            class_annotations = pending_annotations
            class_route = extract_mapping_from_annotations(class_annotations)
            class_tags = extract_api_tag(class_annotations)
            pending_annotations = []
            index += 1
            continue
        if looks_like_method_signature(stripped):
            signature_lines, end_index = collect_signature(lines, index)
            signature_text = "\n".join(signature_lines)
            route = extract_mapping_from_annotations(pending_annotations)
            method_name = extract_method_name(signature_text)
            title, description = extract_api_operation(pending_annotations)
            if route and should_collect_route(class_route, route, method_name, title, description, path):
                method_end = find_method_end(lines, end_index)
                method_start_line = index + 1
                method_end_line = method_end + 1
                family = classify_family(module, controller_name, title, description, route)
                profile = get_family_profile(family)
                display_title = title or f"{class_tags or controller_name.replace('.java', '')} {method_name}"
                display_description = description or class_tags
                params = extract_method_params(signature_text, method_start_line)
                body_lines = [
                    {"line": line_no, "code": lines[line_no - 1].rstrip()}
                    for line_no in range(method_start_line, method_end_line + 1)
                ]
                scenario = {
                    "case_id": build_case_id(path, method_name, route),
                    "scenario_id": build_scenario_id(path, method_name),
                    "family": family,
                    "module": module,
                    "controller_name": controller_name,
                    "class_tags": class_tags,
                    "controller_path": str(path.relative_to(java_root)),
                    "canonical_file_path": normalize_path(str(path.relative_to(java_root.parent.parent.parent))),
                    "class_route": class_route,
                    "route": normalize_route(class_route, route),
                    "method_name": method_name,
                    "title": display_title,
                    "description": display_description,
                    "expectation": "must_not_alert" if "/safe" in route else "must_alert",
                    "expected_severity_band": ["high", "critical"] if "/safe" not in route else [],
                    "sanitizer_expectation": "hard_vulnerability" if "/safe" not in route else "safe_default",
                    "line_start": method_start_line,
                    "line_end": method_end_line,
                    "source": {
                        "kind": "request_input",
                        "line_start": method_start_line,
                        "line_end": min(method_start_line + len(signature_lines) - 1, method_end_line),
                        "params": params,
                        "notes": build_source_notes(params),
                    },
                    "sink": None,
                    "trace": [],
                    "safe_guards": detect_safe_guards(body_lines) if "/safe" in route else [],
                    "rule_type": profile["rule_type"],
                    "aliases": list(profile["aliases"]),
                    "irify_support": "supported" if profile["supported"] else "unsupported",
                    "irify_rule_candidates": [],
                    "scan_observed_rules": {"irify": [], "code_guard": [], "fortify": []},
                    "verification_status": {},
                    "alias_locations": [],
                    "source_refs": [
                        f"{path.relative_to(java_root.parent.parent.parent)}:{method_start_line}",
                    ],
                    "notes": [],
                    "body_lines": body_lines,
                }
                exp, band, sanitizer = recommended_expectation(family, scenario["route"], scenario["safe_guards"], display_description)
                scenario["expectation"] = exp
                scenario["expected_severity_band"] = band
                scenario["sanitizer_expectation"] = sanitizer
                scenario["case_id"] = revise_case_id(scenario["case_id"], exp)
                scenario["title"] = revise_title_for_expectation(scenario["title"], exp)
                scenarios.append(scenario)
                pending_annotations = []
                index = method_end + 1
                continue
            pending_annotations = []
            index = end_index + 1
            continue
        if stripped:
            pending_annotations = []
        index += 1
    return scenarios


def collect_annotation_block(lines: list[str], start: int) -> tuple[list[str], int]:
    block: list[str] = []
    balance = 0
    brace = 0
    index = start
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if index > start and stripped.startswith("@") and balance <= 0 and brace <= 0:
            break
        block.append(line)
        balance += line.count("(") - line.count(")")
        brace += line.count("{") - line.count("}")
        if index == start and balance <= 0 and brace <= 0:
            break
        if index > start and balance <= 0 and brace <= 0 and not stripped.endswith(","):
            break
        index += 1
    return block, index


def collect_signature(lines: list[str], start: int) -> tuple[list[str], int]:
    parts = [lines[start]]
    index = start
    while index + 1 < len(lines) and "{" not in "".join(parts):
        index += 1
        parts.append(lines[index])
    return parts, index


def find_method_end(lines: list[str], start_index: int) -> int:
    balance = 0
    started = False
    for index in range(start_index, len(lines)):
        line = lines[index]
        balance += line.count("{")
        if "{" in line:
            started = True
        balance -= line.count("}")
        if started and balance == 0:
            return index
    return start_index


def looks_like_method_signature(stripped: str) -> bool:
    return stripped.startswith("public ") and "(" in stripped and " class " not in stripped


def extract_mapping_from_annotations(annotations: list[str]) -> str:
    text = "\n".join(annotations)
    match = re.search(r"@(?:GetMapping|PostMapping|RequestMapping)\(\s*(?:value\s*=\s*)?\"([^\"]+)\"", text)
    return match.group(1) if match else ""


def extract_api_tag(annotations: list[str]) -> str:
    text = "\n".join(annotations)
    match = re.search(r"tags\s*=\s*\"([^\"]+)\"", text)
    return match.group(1) if match else ""


def extract_api_operation(annotations: list[str]) -> tuple[str, str]:
    text = "\n".join(annotations)
    value_match = re.search(r"@ApiOperation\(\s*value\s*=\s*\"([^\"]+)\"", text)
    notes_match = re.search(r"notes\s*=\s*\"([^\"]+)\"", text)
    return (value_match.group(1) if value_match else "", notes_match.group(1) if notes_match else "")


def extract_method_name(signature_text: str) -> str:
    match = re.search(r"public\s+[^\(\n]+\s+([A-Za-z0-9_]+)\s*\(", signature_text.replace("\n", " "))
    return match.group(1) if match else "unknown"


def extract_method_params(signature_text: str, start_line: int) -> list[dict[str, Any]]:
    match = re.search(r"\((.*)\)", signature_text, re.S)
    if not match:
        return []
    params_text = match.group(1).replace("\n", " ")
    params = []
    for chunk in split_params(params_text):
        chunk = chunk.strip()
        if not chunk:
            continue
        name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", chunk)
        if not name_match:
            continue
        name = name_match.group(1)
        annotation = extract_param_annotation(chunk)
        type_match = re.search(r"([A-Za-z0-9_<>.?]+)\s+[A-Za-z_][A-Za-z0-9_]*\s*$", re.sub(r"@\w+(?:\([^)]*\))?", "", chunk).strip())
        param_type = type_match.group(1) if type_match else ""
        if param_type in FRAMEWORK_PARAM_TYPES or name in {"request", "response", "session", "model", "userDetails"}:
            continue
        params.append(
            {
                "name": name,
                "type": param_type,
                "annotation": annotation,
                "line_start": start_line,
                "line_end": start_line,
            }
        )
    return params


def split_params(params_text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in params_text:
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        if char in "(<":
            depth += 1
        elif char in ")>":
            depth = max(0, depth - 1)
        current.append(char)
    if current:
        parts.append("".join(current))
    return parts


def extract_param_annotation(text: str) -> str:
    match = re.search(r"@([A-Za-z0-9_]+)", text)
    return match.group(1) if match else ""


def detect_safe_guards(body_lines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    patterns = [
        ("allowlist", "ALLOWED_", "白名单"),
        ("allowlist", "white_list", "白名单"),
        ("denylist", "black_list", "黑名单"),
        ("path-check", "startsWith(", "路径前缀校验"),
        ("path-check", "normalize()", "路径归一化"),
        ("deser-safe-constructor", "SafeConstructor", "安全构造器"),
        ("deser-autotype-off", "setAutoTypeSupport(false)", "关闭 AutoType"),
        ("deser-safe-mode", "setSafeMode(true)", "Fastjson SafeMode"),
        ("validation", "matches(", "正则校验"),
        ("validation", "checkUserInput", "输入校验"),
        ("sql-escaping", "encodeForSQL(", "SQL 转义"),
        ("csp-header", "Content-Security-Policy", "CSP 约束"),
        ("xml-feature", "setFeature(", "解析器安全特性"),
        ("entity-disable", "disallow-doctype-decl", "禁用DOCTYPE"),
        ("entity-disable", "external-general-entities", "禁用外部实体"),
        ("entity-disable", "external-parameter-entities", "禁用参数实体"),
        ("prepared", "PreparedStatement", "预编译"),
    ]
    guards = []
    for item in body_lines:
        code = item["code"].strip()
        if code.startswith("//") or code.startswith("*") or code.startswith("/*"):
            continue
        for guard_type, keyword, description in patterns:
            if keyword in code:
                guards.append({"line": item["line"], "type": guard_type, "description": description, "code": item["code"].strip()})
                break
    return guards[:12]


def build_source_notes(params: list[dict[str, Any]]) -> str:
    if not params:
        return "未识别到显式请求参数，需人工复核"
    return "请求输入参数：" + ", ".join(f"{item['name']}({item['annotation'] or item['type']})" for item in params)


def normalize_route(class_route: str, method_route: str) -> str:
    route = "/".join([class_route.rstrip("/"), method_route.lstrip("/")]).replace("//", "/")
    return route if route.startswith("/") else "/" + route


def build_case_id(path: Path, method_name: str, route: str) -> str:
    controller = path.stem.replace("Controller", "")
    suffix = slugify(route.strip("/").replace("/", "-"))
    return f"JSL-{slugify(controller)}-{slugify(method_name)}-{suffix}".upper()


def build_scenario_id(path: Path, method_name: str) -> str:
    controller = path.stem.replace("Controller", "")
    return f"javaseclab.{slugify(controller)}.{slugify(method_name)}"


def module_name_from_path(path: Path) -> str:
    parts = path.parts
    if "modules" not in parts:
        if "controller" in parts:
            index = parts.index("controller")
            if index > 0:
                return parts[index - 1].lower()
        return "unknown"
    index = parts.index("modules")
    return parts[index + 1] if index + 1 < len(parts) else "unknown"


def is_controller_like(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    if "controller" in parts:
        return True
    name = path.stem.lower()
    if name.endswith("controller") or name.endswith("vul") or name in {"xss", "sqli", "ssrf", "ssti", "xxe", "cors", "csrf", "redirect"}:
        return True
    text = path.read_text(encoding="utf-8", errors="ignore")
    return "@RequestMapping" in text or "@GetMapping" in text or "@PostMapping" in text


def should_collect_route(class_route: str, method_route: str, method_name: str, title: str, description: str, path: Path) -> bool:
    full_route = normalize_route(class_route, method_route).lower()
    text = " ".join([full_route, method_name.lower(), title.lower(), description.lower(), str(path).lower()])
    keywords = ["/vul", "/safe", "/vulnapi/", "漏洞", "安全", "reflect", "upload", "download", "sqli", "ssrf", "xss", "xxe", "ssti", "spel", "idor", "redirect", "deserialization", "csv", "cors", "csrf", "xpath", "jndi"]
    return any(keyword in text for keyword in keywords)


def revise_case_id(case_id: str, expectation: str) -> str:
    if expectation == "should_warn":
        return case_id.replace("-SAFE-SAFE", "-SAFE-WARN").replace("-SAFE1-SAFE1", "-SAFE1-WARN").replace("-SAFE2-SAFE2", "-SAFE2-WARN").replace("-SAFE3-SAFE3", "-SAFE3-WARN").replace("-SAFE4-SAFE4", "-SAFE4-WARN").replace("-SAFE5-SAFE5", "-SAFE5-WARN")
    return case_id


def revise_title_for_expectation(title: str, expectation: str) -> str:
    if expectation == "should_warn" and title.endswith(" safe"):
        return title[:-5] + " 缓释场景"
    return title
