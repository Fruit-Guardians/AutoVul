# Playbook 1: Patch-Guided 补丁反推与差分确认

## 1. 适用场景

当审计线索来源于安全补丁、Git 修复提交、或已公开的 Pull Request 时，宿主需要：
- 从补丁增删的代码反推原漏洞的成因与利用路径；
- 确认该补丁是否有效修补了漏洞；
- 固化漏洞版本命中、修复版本消除的差分确定性证据（`differential` 验证等级）。

---

## 2. 宿主原生自主阶段（无需 AutoVul）

宿主使用自身的 Git 命令、文件阅读、语义理解和模型推理能力：

1. **阅读补丁事实**：
   - 检查提交信息（Commit Message）、PR 描述及改动的 diff。
   - 提取增删的关键逻辑：新增的是校验逻辑（如 `if (!authorized) return;`）、清洗函数（如 `sanitize(input)`）还是状态迁移。
2. **定位上下文代码**：
   - 阅读受影响文件的完整上下文，分析补丁前代码路径的调用者和入参来源。
3. **推导漏洞假设**：
   - 补丁增加了守卫调用？-> 归类为缺失校验（`missing_check`）。
   - 补丁对输入做了转义或过滤？-> 归类为污点数据流传播（`flow`）。
   - 补丁调整了调用顺序或会话重建？-> 归类为协议状态违规（`typestate`）。
4. **自主交付准则**：
   - 若受影响逻辑极简（如单一小函数内部清晰可见），且无需机器可验证的固化证据或 CI 阻断凭据，宿主可直接生成自然语言审计 Finding 交付用户，**无需启动 AutoVul run**。

---

## 3. 触发 AutoVul 的增强条件

当存在以下诉求时，宿主按需调用 AutoVul：
1. **防范语义幻觉**：补丁表面上添加了 `if`，但不确定分支在 CFG 上是否真正主导（dominate）所有执行路径，或存在反向极性逃逸（如 `if (check) return;` 写反导致被绕过）。
2. **生成机器可验证证据**：需要不可变证据（Git 提交指纹、AST 节点坐标、CFG witness）供安全团队、审计报告或无模型 replay 复查。
3. **达成正式差分验证等级**：需由分析器给出严格的 `reproduced`（漏洞版本命中）且 `differential`（修复版本闭环）裁决。

---

## 4. 工具接口与调用规约

### 步骤 A（可选）：轻量结构化观察 (`change_observation`)
若宿主需先提取两版本之间的符号改动结构事实，可调用：
```json
{
  "service": "change_observation",
  "target": {
    "repository": "/path/to/repo",
    "base": "<vulnerable_commit_oid>",
    "head": "<fixed_commit_oid>"
  }
}
```

### 步骤 B：核心差分验证 (`autovul_research`)
以补丁新增鉴权拦截为例，调用 `missing_check` 并在 `mode: "differential"` 下执行：

```json
{
  "action": "execute",
  "capability": "missing_check",
  "hypothesis_version": "autovul.missing-check/1",
  "hypothesis": {
    "schema_version": "autovul.missing-check/1",
    "hypothesis_id": "mcheck-patch-verification-01",
    "language": "javascript",
    "operation": { "kind": "direct_call", "name": "<sensitive_operation>" },
    "required_check": { "kind": "direct_call", "name": "<guard_check_function>" },
    "required_relation": "same_callback_cfg_dominates_operation",
    "scope": {
      "kind": "single_file_named_entry_cfg",
      "file": "src/handlers/target.js",
      "entry": { "kind": "named_function", "name": "handlerFunction" }
    }
  },
  "analyzer_id": "javascript_cfg",
  "mode": "differential",
  "target": {
    "vulnerable": {
      "kind": "git_revision",
      "repository": "/path/to/repo",
      "revision": "<vulnerable_commit_oid>"
    },
    "fixed": {
      "kind": "git_revision",
      "repository": "/path/to/repo",
      "revision": "<fixed_commit_oid>"
    }
  },
  "budget": { "timeout_ms": 15000 },
  "idempotency_key": "patch-verification-run-01"
}
```

---

## 5. 结论回填与假设修正

1. **差分验证成功（`differential`）**：
   - 裁决指标：`verification_level == "differential"`，`decision.outcome == "check_missing"`，且 `decision.fixed_outcome == "check_present"`（`fixed_policy_satisfied == true`）。
   - 宿主操作：在交付用户的审计报告中引用 `run_id` 与证据路径，确认为高确定性已修补漏洞。
2. **未重现或无差异（`generated` / `inconclusive`）**：
   - 检查返回的 `capability_gaps`：
     - 若包含 `MCHECK_UNSUPPORTED_SHORT_CIRCUIT_CONSTRUCT`：说明校验存在三元运算或短路逻辑，宿主应在自然语言报告中指出该复杂度边界，不强行声称已验证。
     - 若包含 `MCHECK_ENTRY_NOT_FOUND`：检查补丁前后的函数重命名，修正 `scope.entry.name` 后重试。
     - 若 `fixed_relation` 依然为 `unchecked_witness`：说明补丁未能有效阻断该敏感操作，宿主可发出“修复不完整/补丁绕过”警告！

---

## 6. 真实端到端案例：OpenClaw CVE-2026-43572

- **组件**：OpenClaw MSTeams Extension (`extensions/msteams/src/monitor-handler.ts`)
- **漏洞说明**：`registerMSTeamsHandlers` 中直接调用 `handleSigninTokenExchangeInvoke`，未先校验发送者身份。
- **补丁 diff**：
  ```diff
   export function registerMSTeamsHandlers(app) {
  +  if (!isSigninInvokeAuthorized(app)) {
  +    return null;
  +  }
     const result = handleSigninTokenExchangeInvoke(app);
     return result;
   }
  ```
- **宿主分析过程**：
  1. 宿主阅读 diff，确认新增检查为 `isSigninInvokeAuthorized`，受保护敏感操作为 `handleSigninTokenExchangeInvoke`。
  2. 宿主向 AutoVul 发起 `missing_check` 差分请求。
  3. AutoVul `javascript_cfg` 分析器判定：
     - 漏洞版本：控制流路径无守卫，命中 `unchecked_witness`；
     - 修复版本：取反分支直接提前 `return`，主导敏感调用，命中 `checked_witness`。
  4. 裁决返回 `verification_level: "differential"`，生成结构化 witnesses 证据。
  5. 宿主向用户输出完整分析报告，证明补丁准确有效。
