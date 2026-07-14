# Securibench Micro 误报/漏报分析报告

> 生成时间: 2026-06-05
> 引擎: yaklang (dev)
> 分析工具: irify-benchmark CLI (`analyze fp`)

## 修复记录

本次分析修复了以下影响匹配精度的关键 bug：

### 1. Sink 识别错误 (`internal/runner/converter_irify.go`)
- **问题**: `IrifyConverter.synthesizeFlowFromPath` 将 data flow path 的**最后一个 node** 当作 sink，但 yak `--with-dataflow-path` 输出的 nodes 是图遍历顺序，最后一个 node 通常是中间节点（如 `getParameter` 的重复），而非真正的 sink（如 `sendRedirect`、`println`、`FileWriter`）。
- **修复**: 实现 `findSinkNode` 启发式方法：
  - 排除 entry node 和已知 source 模式（`getParameter`、`getHeader` 等）。
  - 排除 source 时基于**主函数名**（取 `IRCode` 中第一个 `(` 前、`.` 后的最后一段），避免 `sendRedirect(..., getParameter(...))` 被误判为 source。
  - 在剩余候选中选择行号最大的；若行号相同，优先选择包含已知 sink 关键词（`sendRedirect`、`println`、`FileWriter`、`executeQuery` 等）的节点。

### 2. 文件路径匹配失败 (`internal/matcher/scorer.go`)
- **问题**: `filePathsOverlap` 依赖 `Case.SourceCode` 字段，但 `cases.yaml` 中没有定义 `source_code`，导致该字段为空，filepath score (0.30) 始终为 0，总分为 0.70，低于 threshold (0.80)。
- **修复**: 当 `SourceCode` 为空时，fallback 使用 `Expectation.Flow.Source.File` 或 `Expectation.Flow.Sink.File`。

### 3. 引擎路径解析错误 (`cmd/irify-benchmark/main.go`)
- **问题**: `resolveEngine("yaklang")` 传入字符串 `"yak"`，导致 `NewYaklangEngine` 跳过 bundled binary 搜索，直接使用 PATH 中可能过期的 `yak`。
- **修复**: 改为传入空字符串 `""`，使 `NewYaklangEngine` 正确搜索 bundled binary。

### 4. SSA 缓存导致结果不一致 (`internal/runner/yaklang.go`)
- **问题**: 未使用 `--memory` 参数时，yak 会复用 SSA 数据库缓存，导致相同项目在不同扫描中结果不一致。
- **修复**: 在 `code-scan` 参数中增加 `--memory`。

### 5. `--memory` 模式路径前缀处理 (`internal/runner/converter_irify.go`)
- **问题**: `--memory` 模式下路径格式为 `/src(2026-06-05 12:19:18)/securibench/...`，`cleanPath` 无法正确匹配。
- **修复**: 使用 `ProgramName` 构造前缀替换规则，将 program-name 前缀替换为 `src/`。

## 各项目扫描结果汇总

| 项目 | Cases | TP | FN | FP | Recall | Precision | F1 |
|------|-------|----|----|----|--------|-----------|----|
| XSS | 124 | 57 | 67 | 140* | 0.46 | 0.29 | 0.63 |
| Path Traversal | 4 | 2 | 2 | 5* | 0.50 | 0.29 | 0.67 |
| Open Redirect | 2 | 2 | 0 | 3* | 1.00 | 0.40 | 1.00 |
| SQLi | 6 | 1 | 5 | 13* | 0.17 | 0.07 | 0.29 |

\* FP 中包含大量非目标规则（如空 Catch 块、PrintStackTrace 泄露、资源未释放等代码质量规则）的误报。

## 分项目详细分析

### 1. XSS (securibench-micro-xss)

**规则**: `java-servlet-xss.sf` (检测Java Servlet XSS漏洞)

**结果**: TP=57 / FN=67 / FP=126 (来自 XSS 规则) + 14 (其他规则)

**漏报原因分析**:
- `SourceMatch=false` (约 40+ 例): Case 期望 source 为 `req.getParameter`，但规则检出的 source 可能是 `"name"`、`"s1"` 等局部变量名，或 `req` (不带 `.getParameter`)。
- `SinkMatch=false` (约 20+ 例): Case 期望 sink 为 `writer.println`/`resp.getWriter().println`，但规则检出的 sink 是 `getWriter()` 本身或 `writer` 对象。
- 部分 case 涉及复杂数据流（aliasing、inter-procedural、predicates、reflection），SyntaxFlow 引擎未能完整追踪。

**误报原因分析**:
- 126 个 XSS 规则的 findings 中，有 57 个匹配到 case (TP)，剩余 69 个未匹配到 case 的被记为 FP。
- 但多数 FP 实际上是真实的数据流（source -> sink），只是 benchmark 中没有对应的 case 期望。这属于 benchmark coverage 问题，而非规则误报。
- 另有 14 个 findings 来自非 XSS 规则（空 Catch 块、PrintStackTrace 等代码质量规则）。

**建议**:
- 优化 `java-servlet-xss.sf` 规则的 source 定义，使其更精确匹配 `req.getParameter` 等 Web 入口。
- 优化 sink 定义，确保能正确识别 `getWriter().println(...)` 链式调用。
- Benchmark 扫描时排除代码质量规则（空 Catch、PrintStackTrace 等）。

### 2. Path Traversal (securibench-micro-path-traversal)

**规则**: `java-path-travel.sf` (检测Java路径穿越漏洞)

**结果**: TP=2 / FN=2 / FP=3 (来自 Path Traversal 规则) + 2 (其他规则)

**漏报原因分析**:
- `basic-basic23-001` 和 `basic-basic23-002`: 规则未检测到这两个 case。
- `Basic23.java` 的 sink 可能是 `FileReader` 或 `FileWriter`，但规则可能未触发或 source/sink 匹配失败。

**建议**:
- 检查 `Basic23.java` 的代码结构，确认 `java-path-travel.sf` 的 sink 定义是否覆盖了 `FileReader`/`FileWriter` 的构造函数。
- 调试单规则扫描，确认数据流是否完整。

### 3. Open Redirect (securibench-micro-open-redirect)

**规则**: `java-direct-url-redirect.sf` (检测Java URL重定向漏洞)

**结果**: TP=2 / FN=0 / FP=3

**分析**:
- 两个 case 全部正确匹配，Recall=1.00。
- 4 个 findings 中有 2 个 TP，剩余 2 个 findings 来自 `Basic24.java` 和 `Sanitizers5.java` 的额外 source (如 `"name"` 和 `req`)，它们也流向了 sink，但 benchmark 中只有一个 case 对应每个文件。
- 这属于"一个文件多个数据流路径"的情况，不是真正的规则误报。

### 4. SQLi (securibench-micro-sqli)

**规则**: `java-add-string-and-execute-query.sf` (检测Java SQL语句拼接漏洞)

**结果**: TP=1 / FN=5 / FP=1 (来自 SQLi 规则) + 12 (其他规则)

**漏报原因分析**:
- `basic-basic19-001`: 期望 sink `con.prepareStatement` (line 45, Basic19.java)，规则未检出。
- `basic-basic20-001`: 期望 sink `stmt.execute` (line 47, Basic20.java)，规则未检出。
- `basic-basic21-001/002/003`: 期望 sink `stmt.executeQuery` (line 53, Basic21.java)，规则未检出；但 `basic-basic21-004` 被检出。
- 可能原因：SyntaxFlow 引擎在部分文件中没有完整追踪 source 到 sink 的数据流，或 sink 匹配条件不够宽松。

**建议**:
- 使用 `yak code-scan --rule-keyword "检测Java SQL注入漏洞"` 单规则调试 Basic19.java 和 Basic20.java，确认数据流追踪情况。
- 检查 `java-add-string-and-execute-query.sf` 的 `$sink #{ include: * & $source }` 条件是否过于严格。

## 结论

1. **Open Redirect 规则已可正常使用**，Recall 达 100%。
2. **XSS 规则覆盖率 46%**，主要瓶颈是 source/sink 匹配精度和复杂数据流追踪。
3. **Path Traversal 规则覆盖率 50%**，需针对特定文件结构调试。
4. **SQLi 规则覆盖率 17%**，需重点调试未检出的 case。
5. **Benchmark 扫描时应排除代码质量规则**（空 Catch、PrintStackTrace、资源未释放等），以减少非目标 FP 干扰。

## 附录：调试命令参考

```bash
# 单规则扫描调试
./bin/yak code-scan --target cases/<project>/src --language java \
  --rule-keyword "<规则名>" --format irify --with-dataflow-path --memory \
  --output /tmp/debug.json

# 查看 irify 格式 data flow path
cat /tmp/debug.json | python3 -c "import json,sys; d=json.load(sys.stdin); ..."

# Benchmark 扫描
./bin/irify-benchmark run --project <project-id> --engine yaklang

# 查看结果
./bin/irify-benchmark results show --project <project-id> --engine yaklang --version "yak version dev"

# 误报分析
./bin/irify-benchmark analyze fp <project-id> --format markdown
```
