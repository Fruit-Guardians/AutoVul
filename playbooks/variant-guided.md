# Playbook 4: Variant-Guided 已知漏洞变体发现与候选过滤

## 1. 适用场景

当审计者已知某个漏洞模式（如刚刚验证成功的 1-Day、CVE 或内部漏洞，称作“种子 Seed”），并希望：
- 在当前代码库的其他功能模块、兄弟插件或历史分支中排查同类安全缺陷（变体挖掘）；
- 在相关开源生态或依赖该库的上下游项目中排查类似缺陷；
- 避免机械文本搜索（Text Grep）带来的大量假阳性，借助分析器过滤出“形态极像但实际受到保护”的安全样本，并对真正脆弱的变体给出差分确定性验证。

---

## 2. 宿主原生自主阶段（无需 AutoVul）

宿主使用自身的代码理解与模式泛化能力：

1. **提取种子漏洞特征**：
   - 提取导致漏洞的核心 API 调用（如 `handleSigninTokenExchangeInvoke`）；
   - 提取被遗漏的安全校验（如 `isSigninInvokeAuthorized`）；
   - 识别漏洞触发的上下文范式（如消息监听回调、动作分发器）。
2. **轻量全局摸排**：
   - 宿主可直接使用 ripgrep 或 AST 工具全局检索该敏感 API；
   - 评估候选数量：如果全库只有 1-2 处调用且肉眼即可辨明安全状态，宿主可直接自行复核并完成报告，**无需调用 AutoVul**。

---

## 3. 触发 AutoVul 的增强条件

当存在以下诉求时，宿主按需调用 AutoVul：
1. **多文件/多仓库规模化排查**：候选散布在多个文件或 Git 目标版本中，需要确定性的候选抽取、超时控制与结构化 gap 报告。
2. **需要稳定可追溯的候选身份（Candidate ID）**：需要生成与本地文件系统绝对路径解耦的可移植候选哈希，用于批处理任务分发与进度重放。
3. **消除纯搜索伪造结论（防止裁决通胀）**：Variant Search 自身定位为分析器服务（Analyzer Service），**只返回候选事实，绝不直接判定漏洞**。宿主需要将候选转交回对应的能力层（如 `missing_check`）进行真正的 CFG 差分验证。

---

## 4. 工具接口与调用规约

### 步骤 A：准备合格的种子 Run（Seed Run）
种子必须来自真实验证过的 AutoVul 运行记录，其验证等级必须达到 `reproduced` 或 `differential`（未通过执行验证的 `generated` 种子会被严格拒绝）。

### 步骤 B：发起变体检索 (`variant_search`)
调用 `autovul_research`，选择 `service: "variant_search"`：

```json
{
  "action": "execute",
  "service": "variant_search",
  "seed_run_id": "<previously_verified_seed_run_id>",
  "strategy": "symbol_call_enclosing_scope",
  "strategy_version": "autovul.variant-search-strategy/1",
  "targets": [
    {
      "repository": "/path/to/repo",
      "revision": "<target_commit_oid>"
    }
  ],
  "budget": {
    "max_candidates": 32,
    "timeout_ms": 30000
  },
  "idempotency_key": "variant-search-run-01"
}
```

AutoVul 将返回确凿的候选列表：
```json
{
  "candidates": [
    {
      "candidate_id": "a1b2c3d4...",
      "location": { "file": "extensions/msteams/src/action-handler.ts", "start_line": 12 },
      "enclosing_symbol": { "name": "registerActionHandlers", "kind": "named_function" },
      "matched_symbols": ["handleSigninTokenExchangeInvoke"]
    },
    {
      "candidate_id": "e5f6g7h8...",
      "location": { "file": "extensions/msteams/src/safe-handler.ts", "start_line": 15 },
      "enclosing_symbol": { "name": "registerSafeHandlers", "kind": "named_function" },
      "matched_symbols": ["handleSigninTokenExchangeInvoke"]
    }
  ],
  "completeness": "complete"
}
```

### 步骤 C：将候选转交 Owning Capability 独立验证
宿主遍历各候选，构造独立的 `missing_check` 假设进行确定性差分验证（参见 [Playbook 1](./patch-guided.md)）。

---

## 5. 结论回填与假设修正

1. **确认为真变体（`vulnerable_variant`）**：
   - 候选经 `missing_check` 验证返回 `unchecked_witness`，达到 `reproduced` 或 `differential` 等级。
   - 宿主操作：作为新发现的独立漏洞记录，生成报告并标注与种子的家族谱系关系。
2. **过滤出高相似安全反例（`high_similarity_safe`）**：
   - 候选虽然包含了敏感 API 调用，但 `missing_check` 证实其在控制流图上已具备合法守卫调用（`check_present`）。
   - 宿主操作：明确排除该候选，避免误报干扰开发与安全团队。

---

## 6. 真实端到端案例：OpenClaw MSTeams Token Exchange 变体挖掘

- **家族标识**：`openclaw-token-exchange`
- **种子（Seed）**：`extensions/msteams/src/monitor-handler.ts`（CVE-2026-43572 已验证修复）
- **挖掘目标**：全仓库未审计的 Action 处理器与第三方集成模块
- **宿主分析过程**：
  1. 宿主使用种子运行的 `runId` 发起 `variant_search`。
  2. AutoVul 检索出两处候选：
     - 候选 1：`extensions/msteams/src/action-handler.ts` 的 `registerActionHandlers`
     - 候选 2：`extensions/msteams/src/safe-handler.ts` 的 `registerSafeHandlers`
  3. 宿主针对两处候选分别发起 `missing_check` 差分验证：
     - 候选 1 证实控制流无防护，成功达到 `differential`，确认是一个高危未修补变体！
     - 候选 2 证实存在合法 `isSigninInvokeAuthorized` 阻断，判定为安全反例，无虚假报警。
  4. 宿主向用户输出清晰的家族排查报告，包含 1 个确认变体与 1 个安全证明。
