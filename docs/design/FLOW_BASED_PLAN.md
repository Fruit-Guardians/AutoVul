# Flow-Based 近期规划

- 文档状态：方向实施规划
- 规范状态：Non-normative
- 记录日期：2026-08-28
- 适用项目：AutoVul

> 本文安排 Flow-Based 方向的实施顺序，不定义已接受的产品行为。实现前必须建立并接受 `specs/changes/introduce-flow-model-core/SPEC.md`。方向原则见 [FLOW_BASED_DIRECTION.md](./FLOW_BASED_DIRECTION.md)。

## 已确定的设计

- AutoVul 依附于成熟 Agent/Harness，不实现 Agent Loop。
- v1 是共享流契约、模型/执行分离、CodeQL 可选化和最小断流观察；不是 Flow 研究引擎到齐。
- 产品单元是单条 Source→Sink 流。案例身份、多模型编排和预算汇总留在宿主。
- Flow Model 面向宿主 Agent 和 LLM，采用严格、版本化、字段少的结构化协议。
- Flow Model 只描述漏洞流语义；目标、Analyzer、预算、验证策略和展示字段属于执行请求。
- Analyzer 只返回观察；Core 按固定规则裁决 `flow_status` 和 verification level。
- CodeQL 是首个可选 Analyzer，现阶段不建设 Analyzer Registry 或自动路由。
- 现有 `TaintQueryIntent` 能力必须无损保留，不平行维护两套流语义。
- 既有 verification level、artifact、replay、run 状态机和成功标准继续作为事实标准。
- Core 只返回 revision hint，不生成新的 Flow Model，不自动循环执行。

## 当前与目标状态

| 维度 | 当前实现 | Flow v1 目标 |
| --- | --- | --- |
| 定位 | CodeQL 查询合成与验证 | 单流执行平面；契约提取，不是研究引擎到齐 |
| 模型输入 | `TaintQueryIntent` | Analyzer 无关的 `FlowModel`（闭集 endpoint kind） |
| 执行后端 | 必需的 CodeQL 依赖 | 显式选择的 CodeQL Adapter，可返回能力不可用 |
| 宿主接口 | CodeQL 专属工具 | `autovul_flow`、`autovul_run` |
| 目标输入 | vulnerable/fixed CodeQL database | 执行请求中的版本化 `TargetRef` |
| 结果 | Query/CodeQL 结果 | 复用既有验证等级的 `FlowExecutionResult` |
| 无流反馈 | 原始分析器输出 | 两端观察 + 无路径 + capability mismatch |
| 模型修订 | 宿主提交候选 | 宿主根据校验错误或 revision hint 提交新模型 |

迁移期间保留现有 CodeQL API。Flow API 稳定并完成兼容验证前，不删除、改义或绕过旧接口。

## Flow Model v1

Flow Model v1 保留建立基本流和兼容现有能力所需的最小语义：

```text
FlowModel
├─ schema_version
├─ model_id
├─ language
├─ flow_mode: taint | value
├─ source: FlowEndpoint
├─ sink: FlowEndpoint
├─ steps?: FlowStep[]
└─ barriers?: FlowBarrier[]
```

`FlowEndpoint` 表达端点类型、符号选择、输入输出位置和可选访问路径。`FlowStep` 表达调用、返回、字段或容器等显式传播边。`FlowBarrier` 表达阻断位置和适用条件。

v1 只允许一个 Source 和一个 Sink。多个端点由宿主拆成多个 Flow Model 并编排。Core 不为多模型结果做隐式聚合。真实案例证明拆分造成不可接受的重复后，再单独设计集合语义，并同时规定跨模型预算、差分汇总和 artifact 绑定。

Endpoint kind 必须能用研究语义辩护，不得按 CodeQL matcher 形状无限扩展。新增 kind 的准入见方向文档。

以下内容不进入 v1：

- 多标签 Taint 与 Transform 系统；
- 通用 Summary DSL 和 Model Pack 继承；
- Patch Delta、Variant Search 和跨项目治理；
- 非 Flow 型漏洞的统一抽象；
- Prompt、会话、模型厂商和 Agent 计划。

### 输入校验

Core 只导出一个规范化后的 `FlowModel`。宿主提交的数据在边界上作为 `unknown` 处理：

```text
unknown
  -> validate
     ├─ valid: FlowModel
     └─ invalid: FlowValidationIssue[]
```

不建立正式的 `FlowModelDraft` 类型。校验问题必须包含稳定错误码、字段路径、可修订原因和必要的允许值：

```json
{
  "code": "FLOW_ENDPOINT_POSITION_REQUIRED",
  "path": "/sink/position",
  "message": "call_argument sink requires an argument position",
  "allowed_values": [0, 1, 2]
}
```

## 执行契约

Target、Analyzer 和验证预期不写入 Flow Model：

```text
ExecuteFlowRequest
├─ model: FlowModel
├─ target
│  ├─ vulnerable: TargetRef
│  └─ fixed?: TargetRef
├─ analyzer_id: codeql
├─ mode: probe | reproduce | differential
├─ expectation?
├─ presentation?
│  ├─ message?
│  └─ cwe?
├─ budget
└─ idempotency_key
```

`TargetRef` 指向已经检查并受 trusted-root 约束的分析输入。CodeQL 场景可引用数据库 manifest；路径、数据库格式和 QL Pack 参数由 Adapter 解析。Target 的具体引用格式及现有数据库路径的迁移方式必须在 change SPEC 中确定。

`analyzer_id` 是必填字段。AutoVul 不猜测后端；执行结果必须记录实际 Analyzer、版本和能力信息。

### 结果

```text
FlowExecutionResult
├─ schema_version
├─ run_id
├─ operation_status: completed | blocked | failed | cancelled
├─ flow_status?: connected | disconnected | unknown
├─ verification_level
├─ analyzer
├─ diagnostics[]
└─ evidence_refs[]
```

`verification_level` 复用根 SPEC 的 `generated`、`compiled`、`reproduced`、`differential` 和 `variant_validated`。执行失败、成功但无流、命中但未差分、差分通过必须保持不同状态。

## 断流诊断

诊断只能陈述 Analyzer 实际观察到的内容。建议采用以下层级：

```text
endpoint_observed
no_flow_observed
frontier_observed
missing_summary_hypothesis
capability_mismatch
```

- Source/Sink Probe 可以支持 `endpoint_observed`。
- Analyzer 正常完成但未找到路径，可以支持 `no_flow_observed`。
- `frontier_observed` 必须有传播 trace 或等价工具证据。
- 缺失 Summary、Barrier 过宽等判断默认属于 hypothesis，必须附带依据。
- Analyzer 无法表达语义时返回 `capability_mismatch`，不得静默降级。

候选修订由宿主决定是否采用。AutoVul 不自动改写模型并循环执行。

## 最小宿主接口

```text
autovul_flow
  validate
  execute
    mode: probe | reproduce | differential

autovul_run
  status
  cancel
  replay
```

`validate` 是无副作用的纯校验。`execute` 创建或幂等恢复一次有界运行。`autovul_run` 只处理确定性运行状态，不保存宿主研究计划。

Pi、CLI 和未来宿主调用同一个 Application API。Flow Core 的验收使用宿主无关的契约一致性套件；接入 DeepSeek Harness、MCP 或其他宿主时，另建 change SPEC。

## CodeQL 可选化

近期只定义一个 `FlowExecutionPort`，由 CodeQL Adapter 实现。没有第二个真实 Analyzer 前，不拆分 Compiler、Probe、Analysis 等通用 Port，也不引入注册表。

未安装 CodeQL 时使用明确的 unavailable adapter：

- AutoVul 可以启动并校验 Flow Model；
- 执行请求返回结构化 `CAPABILITY_MISMATCH`；
- Core 不散布 `if (codeql)` 分支；
- 不退回 LLM 猜测、fake runner 或模拟成功。

现有 `ApplicationDependencies.codeql` 如何迁移，必须在 change SPEC 中给出兼容方案。Flow 设计文档不直接授权修改当前构造接口。

## `TaintQueryIntent` 迁移

`TaintQueryIntent` 已包含 Source、Sink、额外传播、Sanitizer 和位置约束。Flow v1 必须复用这些语义资产：

1. 提取共享的 LanguageId、Endpoint、Step、Barrier 和 Location 结构；
2. 保留 `TaintQueryIntent` 的公开 Schema 和现有行为；
3. 对 Flow 语义做无损兼容转换；
4. `cwe`、`message`、`rationale`、证据引用等非流字段留在兼容请求或研究上下文；
5. 无法转换的字段返回明确错误，不得丢弃或猜测。

Core 中只保留一套端点、传播和阻断规则。兼容层负责旧字段投影，CodeQL renderer 最终消费共享语义。

## 实施顺序

### 阶段 0：完成当前变更

- 核对 workflow commit boundary 与 AutoVul rename 的实现状态；
- 补齐 requirement-to-evidence 记录；
- 真实 Analyzer 未验证的项目继续标为未运行，不能用单元测试替代。

### 阶段 1：接受 Flow Model Core SPEC

- 冻结 FlowModel、TargetRef、ExecuteFlowRequest 和 FlowExecutionResult；
- 明确 `TaintQueryIntent` 的无损迁移；
- 定义诊断事实与 hypothesis 的边界；
- 定义 CodeQL 缺失、能力不足、取消和恢复语义。

### 阶段 2：共享契约与兼容层

- 在 `contracts` 中提取共享 Flow 结构，并把语言标识与 CodeQL capability 分开；
- 在 `core` 中实现纯校验和兼容转换；
- 保持现有 CodeQL 工作流、Golden 和 Query Pack 不变；
- 用固定 fixtures 覆盖 LLM 常见缺字段、错枚举和端点歧义。

### 阶段 3：Flow Application API

- 增加 `validate`、`execute` 和运行控制用例；
- 通过单一 `FlowExecutionPort` 接入 CodeQL；
- 保存 Analyzer provenance、诊断和 evidence refs；
- 用现有 differential、Golden 和 replay 验证兼容性。

### 阶段 4：宿主契约验证

- Pi 与 CLI 通过同一 Application API 调用 Flow 用例；
- 使用离线模型输入语料验证首次生成和字段修订；
- 验证中断后凭 run id 和 artifact 恢复；
- 不把第二宿主集成作为 Flow Core 的前置条件。

### 阶段 5：按案例扩展

真实研究案例提出需求后，再评估高级 Summary、Model Pack、Patch Delta、Variant Search、第二 Analyzer 和多标签 Transform。每项能力单独走 change SPEC。

## Flow v1 验收边界

1. 不同宿主适配层提交相同请求时，Core 产生相同语义结果；
2. 无效输入得到字段级、稳定编号且可修订的诊断；
3. Flow Contract 不导入 CodeQL、Pi 或 DeepSeek Harness 类型；
4. 旧 `TaintQueryIntent` 的流语义和现有验证能力不丢失；
5. CodeQL 缺失时，纯校验可用，执行明确 blocked；
6. 结果继续遵守既有 verification level 和证据标准；
7. AutoVul 没有新增模型调用、会话管理、自主计划或开放式循环。
