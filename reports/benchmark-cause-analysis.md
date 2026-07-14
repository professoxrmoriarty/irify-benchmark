# Benchmark 原因导致的误报/漏报分析与优化方案

## 一、当前"Benchmark 原因"误报/漏报全景

本次修复后（sink 识别 + filepath 匹配），四个项目的剩余问题分类：

| 项目 | 规则原因 (FN) | Benchmark 原因 (FN/FP) |
|------|--------------|----------------------|
| XSS | ~65 例（规则未检测到复杂数据流） | ~2 例（case symbol 与引擎输出不匹配） |
| Path Traversal | 2 例（Basic23.java 未触发） | 0 例 |
| Open Redirect | 0 例 | 0 例（已修复） |
| SQLi | 5 例（内置规则 sink 太窄） | 0 例 |

**结论**：本次修复后，"Benchmark 原因"占比已从修复前的 **~100%**（全部 TP=0）下降到 **~3%**。

---

## 二、四类优化方向的分析

### 1. 规范引擎扫描输出（Irify 格式）

**当前问题**：
- `irify` 格式没有明确的 `sink` / `source` 顶层字段
- Sink 需要从 `data_flow_paths[].nodes[]` 中推断，nodes 顺序是图遍历顺序而非数据流顺序
- `IRCode` 是 SSA IR 层面的表示（如 `ParameterMember-parameter[2].getWriter(Parameter-resp)`），不是人类可读的源代码 symbol

**已做的 workaround**：
- `findSinkNode` 启发式方法：排除 entry/source node → 选择最大行号 → tie-break 已知 sink 关键词
- `extractSymbol`：从 `IRCode` 中提取 `-` 后的第二部分

**仍需引擎侧配合的优化**：

```json
// 理想格式：增加明确的 sink/source 标注
{
  "data_flow_paths": [{
    "nodes": [...],
    "sink_node_index": 5,    // <-- 明确标注哪个 node 是 sink
    "source_node_index": 0   // <-- 明确标注哪个 node 是 source
  }]
}
```

或更理想的：

```json
{
  "sink": {
    "symbol": "writer.println",
    "line": 45,
    "file": "src/Basic1.java"
  },
  "source": {
    "symbol": "req.getParameter",
    "line": 38,
    "file": "src/Basic1.java"
  }
}
```

**优先级**：⭐⭐⭐ 长期最优解，但需要跨仓库协调。

---

### 2. 优化引擎输出 → Benchmark 输入（Converter）

**当前问题**：
- `extractSymbol` 逻辑太粗糙：只取 `IRCode` 中第一个 `-` 后的部分
  - `ParameterMember-parameter[2].getWriter(Parameter-resp)` → `parameter[2].getWriter(...)`
  - 与 case 期望的 `writer.println` 差距仍然很大
- `SourceCode` 字段（节点的源代码行）没有被利用

**优化方案**：

#### 2.1 改进 Symbol 提取策略

```go
func extractSymbol(node *irifyDataFlowNode) string {
    // 优先使用 SourceCode 字段（源代码层面的表示）
    if node.SourceCode != "" {
        // "writer.println(s);" → 提取 "writer.println"
        if s := extractCallFromSourceCode(node.SourceCode); s != "" {
            return s
        }
    }
    // Fallback 到 IRCode
    return extractFromIRCode(node.IRCode)
}
```

#### 2.2 增加语义等价映射表

```go
var semanticEquivalents = map[string][]string{
    "getwriter":  {"writer", "resp.getwriter", "parameter.getwriter"},
    "println":    {"writer.println", "out.println", "getwriter.println"},
    "getparameter": {"req.getparameter", "parameter.getparameter", "request.getparameter"},
}
```

在 `symbolsMatch` 中引入语义等价匹配：如果 `expected` 和 `found` 在语义等价表中有交集，视为匹配。

**优先级**：⭐⭐⭐ 中期，纯 irify-benchmark 内部改动，可控。

---

### 3. 优化 Case 定义

**当前问题**：
- Case 的 `expectation.flow.source.symbol` 和 `expectation.flow.sink.symbol` 是手写的人工标注
- 标注基于源代码 AST，而引擎输出的是 SSA IR 表示
- 示例：
  - Case 期望：`writer.println`
  - 引擎输出：`parameter[2].getWriter(Parameter-resp)` / `parameter[2].println(...)`

**优化方案**：

#### 3.1 使用更抽象的 Symbol

将 case 的 symbol 从具体的变量名+方法名，降级为仅方法名：

```yaml
# 当前
sink:
  symbol: writer.println

# 优化后
sink:
  symbol: println
  symbol_context: output   # 可选：标记这是"输出操作"
```

#### 3.2 支持多可选 Symbol

```yaml
sink:
  symbols:
    - writer.println
    - resp.getWriter().println
    - parameter[2].println
```

#### 3.3 自动生成 Case Symbol（半自动化）

提供一个 CLI 工具，运行引擎扫描后，自动将引擎输出的 finding 的 symbol 回填到 case 中：

```bash
./bin/irify-benchmark case sync-symbols --project <id> --engine yaklang
```

**风险**：如果 case symbol 完全按照引擎输出生成，benchmark 会偏向该引擎，失去"引擎无关性"。

**建议**：仅用于辅助标注，最终仍需人工审核。

**优先级**：⭐⭐ 长期，需要人工参与。

---

### 4. 优化匹配器（Matcher）

**当前问题**：
- `symbolsMatch` 使用三层 fallback：精确匹配 → strip args 匹配 → lastPart 匹配 → substring 匹配
- 不理解语义等价（如 `getWriter` 和 `writer` 在输出上下文中等价）
- Threshold 固定为 0.80，对于"source 匹配但 sink 只有 lastPart 匹配"的情况可能太严格
- 存在"误分配"：一个 finding 的 sink 匹配了 case A，但 source 不匹配，导致被分配给 case A 而不是正确的 case B

**优化方案**：

#### 4.1 引入语义等价匹配

```go
func symbolsMatch(expected, found string) bool {
    // 现有逻辑...
    
    // 新增：语义等价检查
    expLower := strings.ToLower(expected)
    fndLower := strings.ToLower(found)
    if areSemanticallyEquivalent(expLower, fndLower) {
        return true
    }
    return false
}
```

#### 4.2 支持正则/通配符 Symbol

```yaml
sink:
  symbol: "*.println"
```

Matcher 使用 `filepath.Match` 或正则匹配。

#### 4.3 动态 Threshold

根据 rule 类型调整 threshold：
- XSS：sink 是输出操作，source 是输入操作，threshold 可以适当降低（如 0.70）
- SQLi：sink 是数据库操作，source 是用户输入，threshold 保持 0.80

#### 4.4 解决"误分配"问题

当前 matcher 的逻辑是：先为每个 case 找最佳 finding，再解决冲突。这导致 finding 可能被分配给 sink 匹配的 case，即使 source 完全不匹配。

优化：在 conflict resolution 中增加惩罚项：
- 如果 finding 对 case 的 source 不匹配，降低其分配优先级
- 或者，要求 `SourceMatch=true` 才能进入 conflict resolution

**优先级**：⭐⭐⭐ 中期，纯逻辑优化，不依赖引擎。

---

## 三、综合建议与优先级排序

| 优化方向 | 具体措施 | 工作量 | 依赖 | 优先级 |
|---------|---------|--------|------|--------|
| **匹配器** | 语义等价匹配 + 通配符 symbol + 动态 threshold | 中 | 无 | ⭐⭐⭐ P0 |
| **Converter** | 改进 `extractSymbol`（优先 `SourceCode`）+ 语义映射表 | 中 | 无 | ⭐⭐⭐ P0 |
| **引擎输出** | 与 yaklang 协商增加 `sink_node_index` / `source_node_index` | 大 | 引擎侧 | ⭐⭐ P1 |
| **Case 定义** | 支持多可选 symbol + 抽象 symbol | 小 | 人工审核 | ⭐⭐ P1 |

**短期（本周可完成）**：
1. 在 `symbolsMatch` 中引入语义等价匹配（解决 `getWriter` vs `writer` 等常见 mismatch）
2. 改进 `extractSymbol`，优先使用 `SourceCode` 字段
3. 在 `analyze fp` 报告中增加"Benchmark 原因 vs 规则原因"的分类统计

**中期（需引擎侧配合）**：
1. 推动 yaklang 在 `irify` 格式中明确标注 sink/source node index
2. 规范 `IRCode` 的生成，使其更接近源代码层面的 symbol
