# AutoVul 宿主语义审计 Playbooks

AutoVul V2 秉持 **“Agent 原生审计优先、AutoVul 按需确定性增强”** 的核心定位。

宿主 Agent 负责代码理解、上下文探索、漏洞假设形成和最终的自然语言交付。宿主**不需要**以调用 AutoVul 或创建 CodeQL 数据库作为审计的前置条件；当代码逻辑清晰或模型自身推理充分时，宿主可直接向用户交付语义审计结论。

只有在需要结构化校验、轻量或深度分析、差分验证、证据固化或无模型 replay 时，宿主才按需调用 AutoVul。

```text
宿主原生代码审计（阅读、搜索、语义推理、形成初步结论）
  │
  ├─> 结论充分，无须确定性验证 ──────> 直接交付用户
  │
  └─> 需要确定性验证或证据固化（按需选择 Playbook 逐级增强）
        ├─> [1. Patch-Guided](./patch-guided.md)     : 补丁反推漏洞与差分确认
        ├─> [2. Sink-Guided](./sink-guided.md)       : 危险调用回溯与跨过程数据流确认
        ├─> [3. Protocol-Guided](./protocol-guided.md)   : 状态机/生命周期违规与序列违规确认
        └─> [4. Variant-Guided](./variant-guided.md)    : 已知漏洞变体发现与候选过滤
```

## 四个 Playbook 概览

| Playbook | 适用场景 | 对应 Capability / Service | 验证等级目标 |
| --- | --- | --- | --- |
| [Patch-Guided](./patch-guided.md) | 已有安全补丁或提交历史，需要反推漏洞机理并证明修复有效性 | `change_observation` -> `missing_check` / `flow` / `typestate` | `differential` |
| [Sink-Guided](./sink-guided.md) | 从高危操作（命令注入、SQLi、反序列化、SSRF）回溯不可信输入路径 | `flow`（CodeQL 引擎） | `reproduced` / `differential` |
| [Protocol-Guided](./protocol-guided.md) | 有状态资源（会话、认证凭据、文件/锁、对象生命周期）的时序违背 | `typestate`（单资源身份敏感） | `reproduced` / `differential` |
| [Variant-Guided](./variant-guided.md) | 已知某一处漏洞已被验证，在代码库或上下游多仓库中寻找同构变体 | `variant_search` -> 宿主筛选 -> owning Capability | `variant_validated` / `differential` |

## Playbook 结构规范

每个 Playbook 均遵循五维标准结构：

1. **宿主自主阶段（Host Autonomous Phase）**：明确宿主只靠自身文件阅读、Git 工具、代码搜索和语义推理完成的工作；何时可以直接交付，不调用 AutoVul。
2. **触发条件（Trigger Conditions）**：明确在什么情况下宿主应发起 AutoVul 增强（如需不可变 Git 证据、跨过程防幻觉判定、差分反例证明或防篡改 replay）。
3. **调用接口与参数（Invocation Specification）**：明确调用的工具名（`autovul_research` / `autovul_run`）、Capability/Service 名、输入参数及分析器选择。
4. **结论回填与修正（Verdict Backfill & Revision）**：说明拿到结构化 observation 与 decision 后的处理逻辑；如何修正假设，如何将验证结论升级并反映在最终审计报告中。
5. **真实端到端案例（End-to-End Real Case）**：提供已验证的真实开源 CVE 案例示范。
