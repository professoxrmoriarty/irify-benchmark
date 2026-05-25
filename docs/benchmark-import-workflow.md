# Benchmark 靶场导入工作流程

记录将外部安全靶场导入 irify-benchmark 的实际操作步骤。

## 前置条件

- `irify-benchmark` CLI 可用：`make build` 编译出 `bin/irify-benchmark`
- Git、Python 3（用于批量生成 case create 命令）

## 实际操作流程

### 1. 克隆靶场仓库

```bash
git clone --depth 1 <repo-url> /tmp/<repo-name>
```

### 2. AI 浏览代码结构

用 Shell + ReadFile 工具并行操作：

```bash
# 看目录结构
find /tmp/<repo-name>/src -type d | sort

# 看有哪些源文件
find /tmp/<repo-name>/src -type f -name "*.java" | wc -l

# 按目录统计文件数
find /tmp/<repo-name>/src -type f -name "*.java" | sed 's|/[^/]*$||' | sort | uniq -c | sort -rn
```

然后读几个代表性文件，了解代码模式：
- 基类/接口（如 `MicroTestCase.java`, `BasicTestCase.java`）
- 一个简单 case（如 `Basic1.java`）
- 一个复杂 case（如带多个 `/* BAD */` 的文件）
- 一个跨文件 case（source 和 sink 在不同文件）

### 3. 用 AI 判断 source、sink、漏洞类型

不要依赖正则脚本。AI 读代码后判断：

**Source**：找外部输入进入代码的位置
- `req.getParameter()` / `getHeader()` / `getCookies()`
- `getServletConfig().getInitParameter()`
- `getServletContext().getInitParameter()`
- `ServletInputStream` / `getInputStream()`
- 其他非常规输入点

**Sink**：找敏感操作的位置
- `writer.println()` → XSS
- `stmt.execute()` / `prepareStatement()` → SQLi
- `Runtime.getRuntime().exec()` → CMDi
- `new FileWriter()` / `FileInputStream()` → Path Traversal
- `sendRedirect()` → Open Redirect

**一个文件有多个 `/* BAD */`** → 拆成多个 cases，每个 marker 一个 case

### 4. 问用户：拆多个 project 还是单个 project

根据分析结果给出推荐：

| 场景 | 推荐 |
|------|------|
| 统一套件，漏洞分散在不同 package（如 Securibench Micro） | **多 project** |
| 按 CWE 分目录（如 Juliet Test Suite） | **单 project** |
| 小 demo（< 20 文件） | **单 project** |

等用户确认后再继续。

### 5. 生成规划 JSON

用 Python 脚本把分析结果写成 JSON，作为后续批量导入的依据：

```python
import json

plan = {
    "source_repo": "https://github.com/...",
    "projects": [
        {
            "id": "securibench-micro-sqli",
            "name": "Securibench Micro SQLi",
            "language": "java",
            "files": ["securibench/micro/BasicTestCase.java", "..."],
            "cases": [
                {
                    "case_id": "basic-basic20-001",
                    "name": "Basic20 #1",
                    "description": "simple SQL injection",
                    "source_file": "securibench/micro/basic/Basic20.java",
                    "source_line": 41,
                    "source_symbol": "req.getParameter",
                    "sink_file": "securibench/micro/basic/Basic20.java",
                    "sink_line": 47,
                    "sink_symbol": "stmt.execute",
                    "cwe": "CWE-89",
                    "tags": ["sqli", "java", "securibench"]
                }
            ]
        }
    ]
}

with open("/tmp/plan.json", "w") as f:
    json.dump(plan, f, indent=2)
```

### 6. 准备临时目录并导入 project

```bash
# 创建临时目录，复制该 project 需要的文件 + 共享基类
mkdir -p /tmp/import-<project-id>
cp -r /tmp/<repo-name>/src/securibench/micro/BasicTestCase.java /tmp/import-<project-id>/
cp -r /tmp/<repo-name>/src/securibench/micro/MicroTestCase.java /tmp/import-<project-id>/
cp -r /tmp/<repo-name>/src/securibench/micro/basic/Basic20.java /tmp/import-<project-id>/
# ... 复制其他该 project 需要的文件

# 导入
cd /path/to/irify-benchmark
./bin/irify-benchmark project import \
  --id securibench-micro-sqli \
  --name "Securibench Micro SQLi" \
  --language java \
  --from /tmp/import-securibench-micro-sqli
```

### 7. 批量创建 cases

用 Python 读 plan JSON，循环调用 `case create`：

```python
import json
import subprocess

with open("/tmp/plan.json") as f:
    plan = json.load(f)

binary = "/path/to/irify-benchmark/bin/irify-benchmark"

for project in plan["projects"]:
    for case in project["cases"]:
        cmd = [
            binary, "case", "create",
            "--project", project["id"],
            "--id", case["case_id"],
            "--name", case["name"],
            "--description", case["description"],
            "--vuln-desc", case.get("vuln_description", case["description"]),
            "--language", project["language"],
            "--source-file", case["source_file"],
            "--source-line", str(case["source_line"]),
            "--source-symbol", case["source_symbol"],
            "--sink-file", case["sink_file"],
            "--sink-line", str(case["sink_line"]),
            "--sink-symbol", case["sink_symbol"],
            "--cwe", case["cwe"],
            "--tags", ",".join(case["tags"]),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"FAIL {case['case_id']}: {result.stderr.strip()[:100]}")
        else:
            print(f"OK {case['case_id']}")
```

### 8. 处理失败的 cases

常见失败原因：

**`source_line` 为 0 或 `source_symbol` 不匹配**
- 原因：source 不是常见的 `req.getParameter`，而是 `getInitParameter`、`getHeaders`、`getServletContext()` 等
- 解决：读该文件的具体代码，找到实际的 source 行和符号，重新 `case create`

**`source file not found`**
- 原因：sink 在文件 B，但 source 在文件 A，文件 A 没被复制到 project 中
- 解决：`cp 文件A /path/to/cases/<project-id>/src/...`，然后重新 `case create`

**`sink symbol not found on line X`**
- 原因：行号对错了（如把 `}` 的行当成了 sink 行）
- 解决：重新读文件确认 `/* BAD */` 所在的准确行号

### 9. 验证

```bash
./bin/irify-benchmark case validate --project <project-id>
```

期望输出：`N case(s) checked, 0 error(s), 0 warning(s)`

Warnings 可以忽略的情况：
- "source line is after sink line" → field assignment / reflection 的正常模式
- "source symbol not found" → 只要行号对，symbol 是 substring 匹配失败的 warning 不影响功能

## 实际数据参考

Securibench Micro 导入结果：

| Project | 文件数 | Cases | 验证结果 |
|---------|--------|-------|---------|
| `securibench-micro-open-redirect` | 4 | 2 | 0 errors |
| `securibench-micro-path-traversal` | 4 | 4 | 0 errors |
| `securibench-micro-sqli` | 5 | 6 | 0 errors |
| `securibench-micro-xss` | 102 | 124 | 0 errors, 9 warnings |

## CLI 速查

```bash
# Project
./bin/irify-benchmark project import --id <id> --name "..." --language java --from <path>
./bin/irify-benchmark project delete --id <id>
./bin/irify-benchmark project list

# Case
./bin/irify-benchmark case create --project <id> --id <case-id> [flags...]
./bin/irify-benchmark case validate --project <id>
./bin/irify-benchmark case delete --project <id> --case <case-id>

# Pipeline
./bin/irify-benchmark scan --project <id> --engine yaklang
./bin/irify-benchmark match --project <id> --engine yaklang --version <v>
./bin/irify-benchmark run --project <id> --engine yaklang
```
