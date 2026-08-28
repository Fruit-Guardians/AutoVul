# Flow-Based 漏洞研究方向

- 文档状态：方向性设计说明
- 规范状态：Non-normative
- 记录日期：2026-08-28
- 适用项目：AutoVul

> 本文记录项目方向，不构成已接受的产品行为。公开契约、工作流、artifact、Analyzer 和能力声明的改动，必须通过独立 change SPEC 接受后实施。近期顺序见 [FLOW_BASED_PLAN.md](./FLOW_BASED_PLAN.md)。

## 项目定位

AutoVul 是附庸于成熟 Agent/Harness 的漏洞研究执行平面。Flow 是第一条、也是当前最完整的研究语义，不是整个产品的唯一分析范式。

Pi Agent、DeepSeek Harness 等宿主负责理解代码、形成漏洞假设、选择工具、修订模型和决定下一步。AutoVul 接收结构化 Flow Model，执行有边界的分析，保存运行状态，返回观察、诊断与验证结果。

```text
Host Agent / LLM
  -> 形成或修订 Flow Model
  -> 调用 AutoVul
       -> 校验模型
       -> 调用 Analyzer，得到观察
       -> Core 按固定规则裁决
       -> 固化结果与 artifact
  -> 根据结构化结果继续研究
```

项目不实现模型供应商框架、Agent Loop、会话记忆、通用计划、子 Agent 编排或通用文件与 Web 工具。CLI 服务于调试、CI 和 replay，不接受“持续寻找漏洞”一类开放目标。

## v1 是什么，不是什么

现有 `TaintQueryIntent` 已经包含 Source、Sink、额外传播、Sanitizer 和位置约束。Flow v1 的正当增量不是“终于有了 Source–Sink”，而是：

1. 抽出 Analyzer 无关的共享流契约，语言标识与 CodeQL capability 分开；
2. 模型、执行请求和结果分离；目标、Analyzer、预算、验证策略不写入模型；
3. CodeQL 变为显式、可缺席的 Adapter；缺席时执行明确 blocked，校验仍可用；
4. 宿主接口收敛为 `autovul_flow` / `autovul_run`；
5. 无流时返回可修订的结构化诊断，而不是只给“未命中”。

v1 **不是** Flow 研究引擎到齐。精确传播前沿、Summary DSL、条件 Barrier、Patch Delta、多端点集合、第二 Analyzer 和 Model Pack 都不在 v1 预设范围。

若实现结束后，宿主在无流时仍然只能读 SARIF 猜测下一轮修订，则 Flow v1 只完成了契约换皮，不能称为核心研究能力。

## Flow 是核心研究语义

Flow 描述一项漏洞假设中的数据或值如何到达危险操作：

```text
Source
  -> Propagator / Summary
  -> Transform
  -> Barrier / Guard / Sanitizer
  -> Sink
```

Source–Sink 是骨架。完整研究还可能涉及访问路径、调用与返回、字段和容器传播、条件约束、上下文以及阻断语义。长期价值在于把这些假设变成可执行、可诊断和可重放的模型。

Flow-Based 适合注入、路径、SSRF、反序列化、文件访问、敏感数据泄露和部分大小传播问题。权限逻辑、业务状态机、TOCTOU、资源生命周期、密码学和部署配置不应被强行塞进 Source–Sink。未来引入其他分析范式时，应作为并列能力单独设计，不得为了统一品牌而改写为 Flow。

## 产品单元是单条流

v1 的产品单元是 **一条已声明的 Source→Sink 流**，不是一个漏洞案例。

- 一个 Flow Model 只有一个 Source 和一个 Sink。
- 多个等价端点由宿主拆成多个模型并编排。
- 案例身份（CVE、issue、研究目标、多模型预算汇总）留在宿主。
- Query Pack 继续绑定一条已验证流及其证据，不在 v1 引入案例级打包。

这与“宿主掌握研究控制权”一致。真实案例证明拆分造成不可接受的重复后，再单独设计集合语义，并同时规定跨模型预算、差分汇总和 artifact 绑定。在此之前，Core 不为多模型结果做隐式聚合。

## 面向 Agent 和 LLM

Flow Model 是宿主与 AutoVul 之间的领域协议。它需要便于 LLM 生成和修订，也要满足确定性执行：

- 严格、版本化的 Schema；
- 字段少，枚举和判别类型明确；
- 校验错误带稳定错误码和字段路径；
- 执行无流时带可修订的结构化诊断，不只是校验错误；
- 紧凑结果返回宿主，完整输出进入 artifact；
- 不包含 Prompt、模型厂商、会话历史、推理过程或 Agent 计划；
- 不包含 QL 语法、数据库路径和宿主 SDK 类型。

未校验的模型输出只是边界输入。Core 将 `unknown` 解析为规范化 `FlowModel`，或返回可修订的 `FlowValidationIssue[]`，不维护另一套 Draft 领域类型。

LLM 修订环有两段，不能只做第一段：

```text
validate 失败  -> 字段级 FlowValidationIssue
execute 无流   -> 观察级诊断（哪端缺失 / 两端都在但不相连 / 能力不匹配）
宿主决定是否提交新的 Flow Model
```

## 模型、执行与展示分离

```text
FlowModel
  source + sink + steps + barriers

ExecuteFlowRequest
  model + target + analyzer + mode + budget
  + 可选 presentation（query message / cwe 等展示字段）

FlowExecutionResult
  operation status + flow status + verification level
  + 观察摘要 + revision hints + evidence
```

Flow Model 只表达漏洞流语义。vulnerable/fixed 目标、Analyzer 选择、超时、验证预期和 replay 身份属于执行请求。同一模型可以用于目标的不同版本，也可以在后续由其他 Analyzer 消费。

`cwe`、`message`、`rationale` 不是流语义。它们不得回到 Flow Model。CodeQL path-problem 和 Query Pack 仍需要展示文本时，由执行请求中的可选 `presentation` 或兼容层提供。Adapter 不得编造 message；缺省时使用稳定、非研究结论的占位，并记录来源。

结果继续使用根 SPEC 定义的验证等级：

- `generated`
- `compiled`
- `reproduced`
- `differential`
- `variant_validated`

操作失败、Analyzer 正常完成但无流、目标命中和差分通过必须分别表达。Flow API 不建立第二套相互竞争的成功等级，也不另起一套 run 状态机。

`compiled` 是 `reproduce` / `differential` 的中间相，由 Core 记录。v1 不提供“只编译、不分析”的独立宿主 mode；需要该行为时另开 change SPEC。

## 宿主与 AutoVul 的边界

### 宿主负责

- 理解用户目标、源码、补丁和业务语义；
- 提出 Source、Sink、传播和阻断假设；
- 选择目标、Analyzer 和分析范围；
- 在多个单流模型之间做案例级编排；
- 判断是否采用修订 hint；
- 决定继续、换方向、扩大范围或停止；
- 管理模型、会话、上下文和通用工具；
- 向用户解释最终结论。

### AutoVul 负责

- 校验版本化 Flow Contract；
- 执行 Source/Sink Probe 和连通分析；
- 管理超时、取消、预算、锁和恢复；
- 返回路径观察、能力缺口和断流诊断；
- 执行 vulnerable/fixed 差分与 replay；
- 保存结构化状态、Analyzer provenance 和 artifact；
- 依据固定规则判断验证等级。

AutoVul 可以返回 **revision hint**（字段路径、原因、可选约束）和允许的后续动作类型（例如 `revise_barrier`、`probe_source`）。Core **不得**产出一份新的 `FlowModel`，也不得自动改写模型并循环执行。开放式目标选择、语义判断和是否继续仍由宿主控制。

```text
Research Control Plane              Research Execution Plane

Host Agent / Harness               AutoVul
├─ 用户意图                        ├─ Integration Adapter
├─ 漏洞假设                        ├─ Application API
├─ Flow Model 修订       request   ├─ Flow Core（裁决）
├─ 工具与目标选择        ───────>  ├─ FlowExecutionPort
├─ 是否继续              <───────  │  └─ CodeQL Adapter（可选）
└─ 最终表达               result   └─ Runtime / Artifact / Replay
```

## 观察与裁决

Analyzer 不得自行定义产品成功。`FlowExecutionPort` 只返回观察，Core 只依据观察和固定规则写入 `flow_status` 与 `verification_level`。

```text
FlowExecutionPort
  execute(request) -> FlowAnalyzerObservation
```

v1 观察至少包含：

```text
FlowAnalyzerObservation
  compile_accepted: boolean | not_run
  source_endpoints: observed locations | not_found | not_run
  sink_endpoints: observed locations | not_found | not_run
  path_observed: true | false | not_run
  capability_gaps: unexpressable model parts
  evidence_refs
  analyzer provenance
```

Adapter 不得返回 `connected`、`differential` 或等价产品结论。Core 将观察映射为结果；映射规则属于领域政策，不属于 Renderer 或宿主适配层。

没有第二个真实 Analyzer 前，不建立注册表，不拆分通用 Compiler/Probe/Analysis Port，也不设计自动能力协商。未配置 CodeQL 时使用 unavailable adapter，执行返回明确能力错误；纯模型校验仍可使用。

后端无法表达某项语义时必须返回 `capability_mismatch`。不得静默忽略 Barrier、传播边或上下文，也不得用 LLM 推理、mock 或参考查询补成成功结果。

## 最小 Application API

近期宿主接口保持两个聚合入口：

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

`validate` 不创建运行，不调用 Analyzer。`execute` 启动或幂等恢复一次有预算的确定性工作流。`autovul_run` 只管理运行状态，不保存宿主研究计划。

Pi、CLI 和未来宿主都是薄适配层，负责注册、参数转换、取消信号和呈现。它们调用同一个 Application API，不复制验证逻辑。DeepSeek Harness、MCP 等新集成仍需独立 change SPEC。

当前 `codeql_database`、`codeql_workflow` 和 `codeql_query` 在迁移 SPEC 接受前继续作为兼容接口。Flow API 稳定后，旧接口必须投影到同一 Core，而不是保留第二套验证逻辑。

`FlowRun` 是现有确定性工作流状态在 Flow 用例上的投影，不是并行 run 系统。`model_id`、现有 `spec_id` / `candidate_id`、`run_id` 和 Query Pack 的对应关系必须在 change SPEC 中写明。v1 不把案例级身份引入 Core。

## Endpoint 本体论

Flow Model 独立于 QL 语法和数据库路径，不表示可以按 CodeQL matcher 形状无限加 kind。

现有 `TaintMatcher` 已经带有 CodeQL 方言痕迹。共享 `FlowEndpoint` 只允许能用研究语义辩护的闭集，例如：调用、调用实参、返回值、函数、参数、字段/属性、环境、容器元素。语言特有约束（如 Python `shell=True`）作为端点上的可选约束，不升格为新的分析器私有 kind。

新增 endpoint / step / barrier kind 必须满足至少一条：

1. 当前闭集无法表达一个真实研究案例；或
2. 第二 Analyzer 无法映射现有 kind，且该差异属于流语义而非工具参数。

不得因为某种 QL 写法更方便而扩展契约。“Analyzer 无关”的检验是：kind 能在不提及 QL 的情况下讲清楚研究含义，并且 Adapter 对无法映射的 kind 返回 `capability_mismatch` 而不是改写语义。

## 断流诊断

“没有连通”是研究结果，但不能直接证明缺少 Summary。诊断必须区分观察和 hypothesis。

v1 **必须**让宿主在无流时区分以下观察，且尽量带地点：

```text
source_observed / source_not_found
sink_observed / sink_not_found
endpoints_observed_without_path
capability_mismatch
```

对应到诊断类别：

```text
endpoint_observed
no_flow_observed
capability_mismatch
```

这是 v1 相对现有 intent 的研究能力增量。没有它，LLM 修订环没有新信息。

v1 **不要求**精确传播前沿。以下内容可以出现为带依据的 hypothesis，不得写成工具事实：

```text
missing_summary_hypothesis
barrier_too_wide_hypothesis
context_mismatch_hypothesis
```

`frontier_observed` 必须来自 Analyzer trace 或等价工具证据。v1 若拿不到可靠前沿，就省略该诊断，不得用 LLM 或启发式路径猜测冒充。

Probe 只证明端点或局部语义存在。验证等级提高仍依赖端到端连接、预期位置、vulnerable/fixed 策略和独立 replay。

## 与 `TaintQueryIntent` 的关系

Flow Model 不能通过删减现有流字段来获得“通用性”。

迁移应提取共享的 LanguageId、Endpoint、Step、Barrier 和 Location 语义，把语言标识与 CodeQL capability 分开，保留旧 Schema 与行为，再由兼容层做无损投影。无法转换的字段返回明确错误，不得丢弃或猜测。

`cwe`、`message`、`rationale` 和证据引用留在兼容请求、研究上下文或 `ExecuteFlowRequest.presentation`。Core 最终只维护一套流语义。CodeQL renderer 消费共享模型，旧接口继续满足现有 Golden、differential、Query Pack 和 replay 要求。

## 运行状态与证据

AutoVul 可以保存确定性工作流状态：

```text
FlowRun
  phase
  operation mode
  analyzer budget
  checkpoint
  verification level
```

这些字段描述一次已请求操作的执行位置。用户目标、对话历史、下一步策略、多模型案例汇总和子 Agent 分工不进入运行状态。

运行时继续遵守现有原则：

- 稳定 run id 和幂等键；
- 超时、取消和完整子进程树清理；
- trusted-root 与 symlink escape 防护；
- 原子 artifact 和可恢复 projection；
- 有界输出、预算、并发与重试；
- 模型输出作为 hypothesis，工具观察作为证据。

## 长期方向

Flow v1 稳定后，可以按真实研究案例增加：

1. 传播前沿和更精确的断流定位；
2. Summary、Propagator 与条件 Barrier；
3. Patch 驱动的 Flow Delta；
4. 同仓库、fork 和下游变体搜索；
5. 多标签 Taint 与 Transform；
6. 第二 Analyzer 与能力损失报告；
7. 经过正负样本和 replay 验证的 Model Pack；
8. 多端点集合语义，以及跨模型预算与差分汇总。

这些能力不进入 Flow v1 的预设范围。新增第二 Analyzer 后，再根据真实差异调整 Port；新增模型资产后，再设计 Pack 生命周期。v1 最小断流观察不在此列，它是 v1 验收的一部分。

## 当前实施门槛

`harden-workflow-commit-boundaries` 完成并 Verified 前，不实施 Flow Model Core。提交、恢复和 artifact 一致性是 FlowRun 的基础。

之后建立 `introduce-flow-model-core` change SPEC，至少覆盖：

- FlowModel、TargetRef、执行请求、展示字段和结果契约；
- `FlowAnalyzerObservation` 与 Core 裁决规则；Adapter 不得写入产品成功等级；
- v1 最小断流观察：两端是否命中、两端都在但无路径、capability mismatch；
- revision hint 的形状；明确禁止 Core 生成新的 Flow Model 或自动循环；
- `TaintQueryIntent` 的无损兼容；
- Endpoint 闭集与新增 kind 的准入规则；
- CodeQL 可选化与 unavailable adapter；
- 单流产品单元，以及 `model_id` / 现有 run / Query Pack 的映射；
- Validate、Execute、Status、Cancel 和 Replay 状态；
- verification level、Golden、differential 和 replay 兼容；
- 安全边界、迁移策略和 requirement-to-evidence 映射。

## 设计检查

每项新增设计应回答：

1. 是否属于漏洞研究能力，并保持宿主掌握研究控制权？
2. Flow Model 是否独立于宿主、Analyzer 参数和具体查询语言？kind 能否在不提 QL 的情况下讲清研究含义？
3. Target、Analyzer、预算和停止条件是否在执行请求中明确？
4. 旧 `TaintQueryIntent` 的流语义是否无损保留？
5. 结果是否复用既有验证等级、证据标准和同一套 run 状态？
6. 无流时是否区分工具观察与模型 hypothesis，并给出可修订的最小诊断？
7. 后端能力不足时是否明确 blocked，且没有伪造成功？
8. Adapter 是否只返回观察，Core 是否独自裁决 `flow_status` 和 verification level？
9. 新抽象是否删除了复杂度，还是只增加一层包装？
10. 若无这条诊断，LLM 是否仍只能读原始分析器输出猜测下一轮？

如果设计最终只是把另一份 YAML 转成 QL，它仍是包装层。只有模型、执行、**可修订的断流观察**和验证形成稳定闭环，Flow-Based 才成为 AutoVul 的核心能力。
