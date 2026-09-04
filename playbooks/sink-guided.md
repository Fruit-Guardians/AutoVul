# Playbook 2: Sink-Guided 危险调用回溯与跨过程数据流确认

## 1. 适用场景

当审计从“系统高危能力点”出发进行正向发掘时（例如命令执行、代码求值、文件读写、SQL 查询、SSRF 等），宿主需要：
- 从危险 Sink 点向上回溯调用链，寻找外部不可信输入（Source）；
- 确认输入在传递到 Sink 的过程中是否未经过有效清洗或验证；
- 针对跨过程、包装函数和复杂参数传递，消除大模型的链路幻觉，生成不可变的数据流路径证据（SARIF 轨迹与 `reproduced` 等级）。

---

## 2. 宿主原生自主阶段（无需 AutoVul）

宿主使用自身的代码搜索工具（grep/ripgrep）、文件阅读与语义推理能力：

1. **搜索危险 Sink 调用**：
   - 寻找敏感执行函数：`subprocess.Popen` / `os.system`（Python）、`child_process.exec`（JavaScript）、`Runtime.getRuntime().exec`（Java）、`system` / `popen`（C/C++）。
2. **反向追踪调用关系**：
   - 查看谁在调用该函数，定位上层路由、Controller 或命令行解析逻辑。
3. **识别数据源（Source）与过滤逻辑**：
   - 确定参数是否直接或间接来源于 HTTP 请求体、URL 查询参数、环境变量或配置文件；
   - 检查途中是否有校验函数、正则匹配或类型转换阻断。
4. **自主交付准则**：
   - 若数据流在同一个函数或紧邻的内部调用中清晰传递（如 `req.query.cmd` 直接拼接进 `exec`），且宿主对语法和上下文极具把握，可直接给出语义审计结论与修复建议，**无需启动 CodeQL 或 AutoVul**。

---

## 3. 触发 AutoVul 的增强条件

当存在以下诉求时，宿主按需调用 AutoVul：
1. **跨函数/跨文件深层传播**：数据流穿过多层封装、包装器（如自定义 `safer_popen`）、列表/字典解包或回调函数，模型仅凭纯文本推导容易产生漏报或虚假路径。
2. **需要严密的污点传播证明（SARIF Path）**：安全运营、Bug Bounty 或合规审计需要完整的污点源到汇聚点逐行调用栈证据。
3. **消除清洗器歧义**：代码中存在某种看似校验的函数，但不确定其能否在数据流意义上作为有效 Sanitizer。

---

## 4. 工具接口与调用规约

### 步骤 A：确定 Source/Sink 端点及参数（使用 `nl -ba` 阅读准确行号）
- 准确记录 Source 的位置（文件、行号、参数名或 API 调用）；
- 准确记录 Sink 的位置（文件、行号、被调用的危险 API、哪个参数是污染参数）。

### 步骤 B：发起 Flow 研究能力验证 (`autovul_research`)
调用 `autovul_research`，选择 `capability: "flow"`：

```json
{
  "action": "execute",
  "capability": "flow",
  "hypothesis_version": "autovul.flow/1",
  "hypothesis": {
    "schema_version": "autovul.flow/1",
    "hypothesis_id": "flow-cmd-injection-01",
    "language": "python",
    "source": {
      "kind": "parameter",
      "file": "src/cli/args.py",
      "line": 42,
      "symbol": "parse_user_options",
      "parameter_name": "user_command"
    },
    "sink": {
      "kind": "call_argument",
      "file": "src/utils/exec.py",
      "line": 108,
      "symbol": "execute_shell",
      "callee": "subprocess.run",
      "argument_index": 0
    }
  },
  "analyzer_id": "codeql",
  "mode": "reproduce",
  "target": {
    "vulnerable": {
      "kind": "codeql_database",
      "path": "/path/to/codeql-db"
    }
  },
  "budget": { "timeout_ms": 60000 },
  "idempotency_key": "cmd-injection-run-01"
}
```

*注：亦可通过兼容工具 `codeql_workflow` 与 `codeql_query` 分步执行 `probe`（端点嗅探）、`draft`（LSP 预检）与 `verify`（确定性编译与分析）。*

---

## 5. 结论回填与假设修正

1. **成功命中（`flow_found` / `reproduced`）**：
   - 裁决指标：返回完整的 SARIF 污点传播轨迹，`verification_level == "reproduced"`（若带有修复数据库对比则为 `differential`）。
   - 宿主操作：将 CodeQL 验证的精确污点传播步骤嵌入审计报告，提供权威结论。
2. **端点不匹配（Probe 失败）**：
   - 检查 `probe` 返回的反馈：通常是参数行号微移、或选取的不是真正的 AST 表达式（例如选到了注释行或装饰器行）。
   - 根据 AutoVul 反馈的就近建议端点调整行号。
3. **断流诊断（Probe 命中但端到端无流）**：
   - 宿主借助 AutoVul 返回的断流提示，检查中间是否存在动态封装（如 Python 的 `*args` / `**kwargs` 或字典解包）；
   - 在候选假设中增加有针对性的 `additional_flow_steps`（如 `call_argument -> parameter`），重新验证。

---

## 6. 真实端到端案例：Python 命令注入（CWE-78）

- **组件**：Kohya 训练工具库 (`library/train_util.py`)
- **漏洞说明**：用户传入的训练参数未经充分转义即被用于拼接外部系统命令。
- **宿主分析过程**：
  1. 宿主通过原生 grep 发现 `subprocess.Popen(..., shell=True)` 在自定义包装函数 `run_cmd` 中被调用。
  2. 宿主向上追踪调用栈，发现来自 CLI 配置解析函数中的 `args.custom_script`。
  3. 为消除多层传递的幻觉，宿主构造 `flow` 假设，指定 Source 为配置参数，Sink 为 `run_cmd` 的第一参数。
  4. AutoVul 执行 CodeQL 分析，精准发现经由 3 层中间 helper 函数的数据流路径，生成权威 SARIF 轨迹。
  5. 宿主在报告中明确指出确凿的利用路径，给出参数化调用的修复代码。
