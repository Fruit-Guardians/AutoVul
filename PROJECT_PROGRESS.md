# AutoVul 项目进度与任务清单

- 更新日期：2026-09-04
- 跟踪范围：TypeScript V2 workspace
- 当前阶段：稳定基线已形成，Variant Search 处于实现与验证收口期
- 稳定规范：[SPEC.md](./SPEC.md)
- 协作章程：[AGENTS.md](./AGENTS.md)

本文件记录“已经完成什么、正在做什么、下一步做什么”。它不替代 SPEC：产品行为以根 `SPEC.md` 和已接受的变更 SPEC 为准，能力是否成立以真实证据和 replay 为准。

## 状态口径

| 状态 | 含义 | 能否写入稳定支持列表 |
| --- | --- | --- |
| `Draft` | 方案仍在讨论，不能授权生产实现 | 否 |
| `Accepted` | 范围和约束已批准，可以实施 | 否 |
| `Implemented` | 代码与迁移已完成，真实或完整验证尚未闭合 | 否 |
| `Verified` | 每项要求都有对应证据，未运行项已明确记录 | 可以描述为已验证，但尚未并入根基线 |
| `Archived` | 验证完成，稳定行为已并入根 `SPEC.md` | 是 |

单元测试通过、代码已写、临时 Git fixture 命中，都不能单独把一项工作推到 `Verified`。真实 Analyzer、真实 vulnerable/fixed 或正负样本、独立 replay 等门禁，以各自 SPEC 为准。

## 当前进度总表

| 工作面 | 当前状态 | 已形成的结果 | 尚未完成的门 |
| --- | --- | --- | --- |
| 产品定位与分层 | 稳定 | Agent 原生语义审计是默认路径；AutoVul 是按需研究增强层，Capability、Analyzer Service、Runtime、Integration 分层成立 | 持续防止 Core 长成 Agent、审计准入门、万能 IR 或动态插件框架 |
| 共享确定性运行时 | 稳定 | 运行身份、预算、超时、取消、lease、原子 artifact、恢复、replay 与 Application shutdown 已落地 | `harden-workflow-commit-boundaries` 仍需按 SPEC 完成并验证 |
| Flow v1 | `Archived` | 四语言真实 CodeQL 矩阵、差分、20 个案例、迁移根目录后的无模型 replay | 只做兼容维护；新增语义另开 SPEC |
| MissingCheck v1 | `Archived` | CodeQL 路径的真实 OpenClaw 差分、错误假设修订与 fresh-process replay | 保持窄语义；不把所有鉴权问题泛化为一个守卫模型 |
| Typestate v1 | `Archived` | Ghost 单资源身份敏感状态迁移、正负样本、差分与 replay | 保持单资源、单文件、固定事件边界；扩展需新案例准入 |
| Change Observation v1 | `Archived` | OpenClaw/Ghost 两组真实 Git 对象观察、结构化 gap、迁移 replay | 只返回变化事实，不解释漏洞意义 |
| JavaScript CFG Analyzer | `Verified` | MissingCheck 可不依赖 CodeQL，使用 immutable Git source、AST/CFG、极性、复杂度上限、证据隔离与防篡改 replay 已验证 | 暂不并入根 SPEC，等待统一发布归档；TypeScript 尚不能作为已验证支持宣传 |
| DeepSeek Harness adapter | `Implemented` | 两个聚合工具、结构化错误、提示词和 close 路径已接入统一 Application API | 真实外部 Harness/官方 SDK 边界的注册、执行、取消、replay、shutdown 验收 |
| Variant 角色分类 | `Verified` | 角色已确认归属于 `search_service`，两真实家族与 owning-Capability 验证已闭环 | 暂不并入根 SPEC，等待统一发布归档 |
| Variant Search v1 | `Verified` | 种子严格校验、可迁移 identity、完整 gaps、原子 bundle、两真实家族、高相似反例、owning Capability 差分与独立 replay 已验证 | 暂不并入根 SPEC，等待统一发布归档 |
| 发布状态 | 未进入 RC | 稳定能力基线可用，开发分支上有新增实现 | JavaScript CFG、DeepSeek 的外部验证未闭合，不能标成 `v2.0-rc1` 或“100% 完成” |

## 已完成任务

### 产品与架构

- [x] 确认产品是成熟 Agent/Harness 的漏洞研究能力层，不实现 Agent Loop、模型路由、长期记忆或子 Agent 编排。
- [x] 确认宿主可以依靠自身代码理解完成并交付语义审计；AutoVul 不充当审计准入门，CodeQL 不作为默认前置条件。
- [x] 固定按需升级路径：宿主原生审计 → 轻量 Git/AST/CFG → Capability 验证 → CodeQL 深验 → 动态复现；宿主可以在任一级停止。
- [x] Pi 与 DeepSeek 的通用宿主提示采用 Agent-audit-first；显式 CodeQL 兼容流程继续使用 CodeQL 专用指导。
- [x] 确认 Capability 采用并列领域模型；Flow、MissingCheck、Typestate 分别拥有自己的 Hypothesis、Observation、Decision Policy 和成功谓词。
- [x] 确认共享层只处理运行、预算、取消、锁、artifact、证据与 replay，不解释领域语义。
- [x] 保持 `contracts <- core <- analyzers/runners <- integrations` 单向依赖。
- [x] 将宿主主接口收敛为 `autovul_research` 与 `autovul_run`，旧 `codeql_*` 仅作兼容面。
- [x] 将 CodeQL 定位为可选的深度分析后端，不再把项目边界写成 CodeQL 工作流。
- [x] 将 Delta 归类为 Analyzer Service，并以 Change Observation v1 完成落地。

### 已归档研究能力与服务

- [x] Flow v1：真实 CodeQL probe、vulnerable/fixed differential、20 案例矩阵、artifact 固化和 relocated replay。
- [x] MissingCheck v1：OpenClaw CVE-2026-43572 准入、CodeQL 真实差分、反例、revision hints 和 fresh-process replay。
- [x] Typestate v1：Ghost CVE-2026-70594 准入、同一资源 identity、非法迁移 witness、安全 trace、差分和 replay。
- [x] Change Observation v1：不可变 Git revision 观察、JS/TS 结构事实、OpenClaw/Ghost 真实矩阵和独立 replay。
- [x] Variant Search v1：不可变 Git 候选发现、两真实家族、高相似反例、owning MissingCheck 验证到 differential 与独立 replay。

### 运行时与工程门禁

- [x] 运行状态、稳定 run id、预算、超时和取消语义。
- [x] 每个 run 的互斥操作、Application 幂等关闭和关闭期间拒绝新工作。
- [x] 关键 artifact 原子写入、恢复和损坏阻断。
- [x] Flow、MissingCheck、Typestate、Change Observation、Variant Search 的 route、fingerprint、Analyzer/adapter/policy version 与 evidence immutability replay 基线。
- [x] 架构、依赖、SPEC、命名与 package 输出检查脚本。
- [x] Pi Extension 与 CLI 通过同一 Application API 暴露聚合能力。

## 当前任务清单

### P0 — 收口 Variant 分类与 Variant Search v1（已完成验证）

- [x] 为 OpenClaw 家族写入可复核的 family manifest：`specs/changes/introduce-variant-search-service-v1/evidence/manifests/openclaw-msteams-family.json`。
- [x] 选择并固化第二个真实家族：`specs/changes/introduce-variant-search-service-v1/evidence/manifests/webhook-auth-family.json`。
- [x] 明确 v1 支持的 seed Capability/artifact version；通过正式 Schema 解析，拒绝仅凭字段形状猜测的 seed。
- [x] 校验 seed 至少为真实 `reproduced`，并绑定 verification level、Analyzer provenance、result/evidence digest。
- [x] 给 strategy 增加闭合的版本身份；candidate id 绑定 seed、corpus、revision、strategy/version、location 和 match facts，且不依赖本机绝对仓库路径。
- [x] 对文件截断、候选截断、超时、parser failure、unsupported syntax、不可读对象和 revision 不可用返回准确的 completeness 与结构化 gap。
- [x] 将 route、result、candidate evidence 和 digest 作为一个 bundle 原子提交；失败时不能留下“completed 但证据缺失”的状态。
- [x] replay 预检 route、seed、corpus、strategy、parser/Analyzer/adapter version、resolved budget 和 evidence digest。
- [x] replay 比较完整规范化 observation，不只比较 candidate 数量和 id；验证原 artifact 前后不变，并写入独立 replay namespace。
- [x] 加入高相似安全样本与非 seed 漏洞成员，对比结构策略和 exact/text baseline，记录误报、漏报、预算与宿主选择点。
- [x] 至少将一个非 seed candidate 交给 owning Capability，取得真实 `reproduced` 或 `differential` 结果。
- [x] 完成 Pi、DeepSeek、CLI 的 validate/execute/status/replay 聚合验收。
- [x] 创建 `VERIFICATION.md`，逐项映射 `REQ-VARSEARCH-*` 与 `REQ-VARIANT-*`。
- [x] 所有门闭合后依次推进到 `Verified`。

### P1 — 完成已经存在但未验证的边界

- [x] JavaScript CFG：补真实 OpenClaw differential、fingerprint/evidence mutation replay 与 VERIFICATION.md 逐项映射。
- [x] JavaScript CFG：在真实 TypeScript 案例完成前，文档和提示词严格限定为 JavaScript 语义，不声称 TypeScript 已验证支持。
- [ ] DeepSeek Harness：使用真实 Harness 或官方 SDK fixture 执行工具注册、两个聚合调用、invalid input、取消、replay 和 close。
- [ ] DeepSeek Harness：保存可复核的外部集成记录，再从 `Implemented` 推进到 `Verified`。
- [ ] `harden-workflow-commit-boundaries`：按已接受 SPEC 完成写入故障矩阵、恢复、并发提交和 Query Pack promotion 门。
- [ ] `rename-project-to-autovul`：完成历史 pre-rename artifact/Query Pack 的真实 replay，再决定是否 Verified。
- [ ] `stabilize-architecture-boundaries`：将后续已跑过的真实矩阵逐项映射回该 SPEC；不能只因别的变更通过就自动归档。

### P2 — 下一阶段候选，尚未立项

- [ ] 宿主语义审计 Playbook：在 Pi/DeepSeek Integration 或独立 Skill 中整理 patch-guided、sink-guided、protocol-guided 和 variant-guided 路线；复用宿主文件/搜索能力，不新增模型 Provider、Agent Loop 或 Core 语义审计框架。
- [ ] 轻量 Analyzer：优先围绕规则明确、局部可判定的研究动作立项，例如语法/CFG、Git/patch、依赖事实；每项单独写 SPEC 和 completeness 边界。
- [ ] Dynamic Reproduction Port：先解决隔离、审批、超时、证据和副作用策略，再决定生产接口。
- [ ] MCP Integration：在聚合 Application API 稳定且确有宿主需求后单独立项，不复制 Pi/DeepSeek 领域逻辑。
- [ ] Dependency Intelligence：先定义可重放数据源、版本身份、缓存与离线失败语义。
- [ ] Windows：补路径、进程树清理和 CI 证据前不声明支持。
- [ ] `variant_validated` policy：另写 SPEC 定义最低正样本、负样本、多样性和逐例证据等级。

## 里程碑

| 里程碑 | 内容 | 状态 | 完成条件 |
| --- | --- | --- | --- |
| M0 产品定调 | Agent 原生语义审计、AutoVul 按需增强、并列 Capability、共享 Runtime | `Archived baseline` | 根 SPEC 与章程一致，AutoVul 与 CodeQL 均不成为宿主审计前置条件 |
| M1 Flow v1 | 第一条完整 Capability 语义 | `Archived` | 真实四语言矩阵、差分、artifact、replay |
| M2 MissingCheck v1 | 第二条独立领域语义 | `Archived` | OpenClaw 真实 CodeQL differential 与 replay |
| M3 Typestate v1 | 第三条独立领域语义 | `Archived` | Ghost identity-aware differential 与 replay |
| M4 Change Observation v1 | 第一条支持型 Analyzer Service | `Archived` | 两个真实消费者、无 verdict、relocated replay |
| M5 多 Analyzer | MissingCheck 的轻量 JavaScript CFG 后端 | `Implemented` | 真实 OpenClaw clean-process Golden 与完整 replay 门 |
| M6 第二宿主 | DeepSeek function-calling adapter | `Implemented` | 真实外部 Harness/SDK 验收 |
| M7 Variant Search v1 | verified seed 到 bounded candidates，再交回 owning Capability | `Accepted / in progress` | 两个真实家族、原子证据、完整 replay、owning validation |
| M8 稳定化发布 | 清理未闭合生命周期债务并冻结兼容范围 | `Not started` | 所有发布声明均有 SPEC/证据，工作区 full gate 与外部门禁记录完整 |

## Change SPEC 状态矩阵

当前共有 15 份变更 SPEC：7 `Archived`、1 `Verified`、4 `Implemented`、3 `Accepted`。

| Change SPEC | 类型 | 状态 | 证据或剩余门 |
| --- | --- | --- | --- |
| [`establish-research-capability-architecture`](./specs/changes/establish-research-capability-architecture/SPEC.md) | 架构 | `Archived` | 共享外壳、静态分支、双聚合入口已并入根基线 |
| [`introduce-flow-capability-v1`](./specs/changes/introduce-flow-capability-v1/SPEC.md) | Capability | `Archived` | [逐项验证](./specs/changes/introduce-flow-capability-v1/VERIFICATION.md) |
| [`admit-missing-check-capability-v1`](./specs/changes/admit-missing-check-capability-v1/SPEC.md) | Capability | `Archived` | [逐项验证](./specs/changes/admit-missing-check-capability-v1/VERIFICATION.md) |
| [`admit-typestate-capability-v1`](./specs/changes/admit-typestate-capability-v1/SPEC.md) | Capability | `Archived` | [逐项验证](./specs/changes/admit-typestate-capability-v1/VERIFICATION.md) |
| [`classify-delta-research-role`](./specs/changes/classify-delta-research-role/SPEC.md) | 分类 | `Archived` | `analyzer_service` 分类已由 Change Observation 落地 |
| [`add-change-observation-analyzer-v1`](./specs/changes/add-change-observation-analyzer-v1/SPEC.md) | Analyzer Service | `Archived` | [逐项验证](./specs/changes/add-change-observation-analyzer-v1/VERIFICATION.md) |
| [`add-application-shutdown-semantics`](./specs/changes/add-application-shutdown-semantics/SPEC.md) | Runtime | `Archived` | 关闭、取消与资源释放门已记录在 SPEC |
| [`harden-capability-execution-contracts-v1`](./specs/changes/harden-capability-execution-contracts-v1/SPEC.md) | Contracts/Replay | `Verified` | 要求映射与确定性测试已记录，尚未归档 |
| [`add-missing-check-javascript-cfg-analyzer-v1`](./specs/changes/add-missing-check-javascript-cfg-analyzer-v1/SPEC.md) | Analyzer | `Implemented` | 真实 OpenClaw clean-process Golden 与 `VERIFICATION.md` 待补 |
| [`add-deepseek-harness-integration`](./specs/changes/add-deepseek-harness-integration/SPEC.md) | Integration | `Implemented` | 真实外部 Harness/SDK 验收待补 |
| [`rename-project-to-autovul`](./specs/changes/rename-project-to-autovul/SPEC.md) | Compatibility | `Implemented` | pre-rename 真实 replay 与兼容窗口决策待补 |
| [`stabilize-architecture-boundaries`](./specs/changes/stabilize-architecture-boundaries/SPEC.md) | Architecture | `Implemented` | 历史 SPEC 的真实矩阵映射仍未闭合 |
| [`harden-workflow-commit-boundaries`](./specs/changes/harden-workflow-commit-boundaries/SPEC.md) | Runtime | `Accepted` | 实现、故障注入、并发与真实 Query Pack replay 待完成 |
| [`classify-variant-research-role`](./specs/changes/classify-variant-research-role/SPEC.md) | 分类 | `Accepted` | `search_service` 已选定；两家族分类证据待补 |
| [`introduce-variant-search-service-v1`](./specs/changes/introduce-variant-search-service-v1/SPEC.md) | Analyzer Service | `Accepted` | 实现中；契约、证据、replay 与真实矩阵未收口 |

## 验证快照

| 项目 | 当前记录 |
| --- | --- |
| 最近同步的代码基线 | `9a3c37e`，`main` 与 `origin/main` 同步时的基线 |
| 当前工作区 | 含未提交的 Variant Search、宿主投影、README、包级文档与测试改动 |
| 本轮文档检查 | `spec:check` 通过：125 条根基线要求、15 份变更 SPEC；`naming:check`、文档链接检查和 `git diff --check` 通过 |
| 当前 full gate | 本轮未运行 `npm run check`；当前工作区含实现改动，不能用文档检查替代全量代码门禁 |
| 已归档真实证据 | Flow、MissingCheck、Typestate、Change Observation 各自的 `VERIFICATION.md` 和 evidence 目录 |
| 未闭合真实证据 | JavaScript CFG、DeepSeek 外部宿主、Variant 分类与 Variant Search |

## 下一步执行顺序

1. 先按 `introduce-variant-search-service-v1` 收紧 seed、identity、completeness、atomic artifact 和 replay；这一步不扩大策略数量。
2. 再建立两个真实 variant family manifests，跑结构策略与 exact/text baseline，并用 owning Capability 验证选中的非 seed candidate。
3. Variant 达到 `Verified` 后再归档；根 `SPEC.md` 在此之前不加入 Variant 稳定要求。
4. 补 JavaScript CFG 的真实 OpenClaw gate，决定是否推进到 `Verified`。
5. 补 DeepSeek 真实外部 Harness 验收，确认第二宿主不是“仅兼容 function schema”的名义集成。
6. 收口 workflow commit、rename、architecture stabilization 三项生命周期债务。
7. 以宿主语义审计 Playbook 和提示审查固定 Agent-audit-first 路径，再从轻量 Analyzer、Dynamic Reproduction、MCP、Dependency Intelligence 中选一个立项。每次只引入一个窄边界和一个真实验收案例。

## 文档维护规则

- 根 `SPEC.md` 只接收 `Verified -> Archived` 的稳定行为。
- README 的“支持”措辞不得超过本表和变更 SPEC 的状态。
- 新增或改变公开 Schema、Analyzer、Integration、artifact、预算、安全边界时，先更新或新增 Accepted SPEC。
- 每次状态推进都要同时更新：变更 SPEC 状态、`VERIFICATION.md`、根进度表、README 支持矩阵；只有归档时才更新根 `SPEC.md`。
- 测试数量只记录某次明确执行的快照，不作为永久完成度，也不写“100%”或“全覆盖”这类无法持续证明的表述。
- `docs/` 保持 Git 忽略；需要在远端可见的项目级文档放在仓库根目录或其他已跟踪目录。
