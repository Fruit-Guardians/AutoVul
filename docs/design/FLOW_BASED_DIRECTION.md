# Flow-Based 漏洞研究方向

- 文档状态：方向性设计说明
- 规范状态：Non-normative
- 记录日期：2026-08-27
- 适用项目：PureAutoCodeQL V2

> 本文记录项目当前认可的发展思想，不构成已接受的产品行为，也不授权直接实现。涉及公开契约、工作流、artifact、Analyzer 或能力声明的改动，仍须通过独立的 change SPEC 接受后实施。

## 一句话定位

PureAutoCodeQL 应发展为一个附庸于成熟 Agent/Harness 的 **Flow-Based 漏洞研究引擎**。

宿主 Agent 负责理解代码、形成漏洞假设、选择和修订模型；PureAutoCodeQL 负责把类型化 Flow Model 编译到 Analyzer，执行 Source–Sink 连通分析，诊断断流原因，完成差分验证并搜索同构变体。

项目不建设自己的 Agent，也不以通用安全聊天、通用证据系统或通用任务编排作为当前架构中心。

## 为什么选择 Flow-Based

目前最成熟、最适合确定性执行的漏洞研究对象，不是自然语言 Finding，而是：

```text
什么数据
从哪里进入
经过哪些传播和转换
在什么条件下
到达什么危险操作
为什么没有被正确阻断
```

它可以形式化为：

```text
Source
  -> Propagator / Summary
  -> Transform
  -> Sanitizer / Barrier / Guard
  -> Sink
```

Source–Sink 是核心骨架，但完整 Flow Model 不能退化成两个函数名。它还需要表达访问路径、流标签、调用与返回关系、字段和容器传播、条件约束、上下文以及阻断语义。

## Flow-Based 必须如何体现在系统中

Flow-Based 不是宣传术语，必须同时体现在五个层面。

### 1. Flow Contract

系统的核心研究输入逐步从 CodeQL 查询草稿提升为类型化 Flow Model：

```text
FlowModel
├── Sources
├── Sinks
├── Propagators / Summaries
├── Transforms
├── Sanitizers
├── Barriers / Guards
├── Flow Labels
└── Context Constraints
```

当前 `TaintQueryIntent` 可以在未来 change SPEC 中作为兼容输入，转换到新的 Flow Model，而不是被直接删除或静默改义。

### 2. Flow Workflow

工作流围绕“建立、诊断和验证一条流”展开：

```text
构造 Flow Model
  -> Source Probe
  -> Sink Probe
  -> Propagation Probe
  -> Barrier / Sanitizer Probe
  -> Flow Connection
  -> Flow Diagnosis
  -> Model Revision
  -> Differential Validation
  -> Variant Search
```

Probe 只证明端点或局部语义存在；只有端到端连接满足路径、上下文和差分约束时，才能提高验证等级。

### 3. Flow Compiler

Flow Model 是 Analyzer 无关的中间表示，具体查询只是执行后端：

```text
Flow Model IR
├── CodeQL Compiler
├── Semgrep Compiler
├── Joern Compiler
└── Future Analyzer Compiler
```

项目不应把所有 Analyzer 压缩到最低能力公约数。后端无法表达某项语义时，必须返回结构化的 capability mismatch 或 degraded compilation，而不是静默忽略 Barrier、上下文或跨过程约束。

### 4. Flow Diagnosis

“没有连通”不是普通失败。系统应返回结构化断流诊断，例如：

```text
Source 已命中
Sink 已命中
传播前沿到达 CommandBuilder.command
CommandBuilder.render 缺少 Argument[self].Field[command] -> ReturnValue Summary
```

重点诊断类型包括：

- Source 或 Sink 节点选择错误；
- 参数、返回值或访问路径不匹配；
- 缺失 Summary/Propagator；
- 字段、容器或跨模块传播缺失；
- Sanitizer 或 Barrier 过宽；
- 条件 Guard 分支语义错误；
- 类型、调用上下文或生命周期不匹配；
- Analyzer 后端能力不足。

断流诊断是项目区别于简单 CodeQL/Semgrep 包装层的关键能力。

### 5. Flow Model Pack

项目长期积累的核心资产应是可验证的 Flow Model Pack，而不只是一组 QL 文件：

```text
flow-models/
├── command-injection/
├── sql-injection/
├── path-traversal/
├── ssrf/
├── unsafe-deserialization/
├── file-access/
└── sensitive-data-flow/
```

每个模型包可以包含：

- 通用 Source/Sink 分类；
- 语言和框架端点；
- Summary 和 Propagator；
- Sanitizer、Barrier 和 Guard；
- 常见错误净化方式；
- 正样本、负样本和 differential 样本；
- Analyzer 能力映射；
- 性能和误报约束。

## 与通用模型的关系

PureAutoCodeQL 不与宿主通用模型竞争。两者承担不同工作：

```text
宿主通用模型
  -> 理解漏洞描述、补丁和业务语义
  -> 提出 Source、Sink、传播和阻断假设
  -> 构造或修订 Flow Model

PureAutoCodeQL
  -> 校验模型结构
  -> 编译到具体 Analyzer
  -> 遍历代码与调用关系
  -> 返回连通路径或断流诊断
  -> 执行 vulnerable/fixed 差分
  -> 使用同一模型搜索变体
```

通用模型擅长理解、联想和提出新假设，但难以稳定完成全仓库遍历、跨文件语义追踪、路径证明和重复验证。Flow 引擎提供的是确定性执行和规模化搜索能力。

因此，项目不应宣称 Flow 引擎全面强于通用模型。准确表达是：

> 在 Flow-Based 漏洞研究中，宿主通用模型与确定性 Flow 引擎的组合，应当显著强于通用模型单独阅读代码。

## 先进性来自哪里

Source–Sink、Sanitizer、Barrier 和 Summary 本身都是成熟静态分析概念。仅提供 YAML Source/Sink 并生成 CodeQL 查询，只是有价值的工程封装，不构成项目的长期先进性。

真正需要形成差异化的能力包括：

1. 类型化、Analyzer 无关且不丢失高级语义的 Flow IR；
2. 能解释“为什么没有流”的传播前沿和断流诊断；
3. 根据断流点生成 Summary、Propagator 或 Barrier 修订候选；
4. 支持条件化 Guard、上下文约束和多标签 Taint；
5. 从补丁提取 Source–Sink–Barrier 的 Flow Model Delta；
6. 将已验证 Flow Pattern 用于同仓库、fork 和下游变体搜索；
7. 对不同 Analyzer 的编译结果给出明确能力损失；
8. 通过正负样本、differential 和 replay 管理 Model Pack 质量。

## 多标签与 Transform

Flow Model 不应长期停留在 `tainted=true/false`。建议允许类型化标签：

```text
remote-input
filesystem-path
shell-fragment
sql-fragment
html-fragment
url
credential
serialized-object
allocation-size
```

Transform 可以改变标签或安全属性：

```text
URL decode:
encoded-input -> decoded-input

shell escape:
shell-fragment -> shell-safe-fragment

path normalization:
filesystem-path -> normalized-path
```

Sink 声明其危险输入位置和可接受标签；Sanitizer/Barrier 声明它针对的标签、条件和作用范围。

## Patch 与 Variant 仍然围绕 Flow

Patch Intelligence 不作为脱离 Flow 的第二套中心，而是 Flow Model 的生成和修订来源：

```text
Before: Source -> Transform -> Sink
After:  Source -> Transform -> Barrier -> Sink
```

或者：

```text
Before: attacker input -> shell command string -> shell Sink
After:  attacker input -> argv element -> process API with shell=false
```

系统由此提取：

- 新增或收紧的 Barrier；
- 被替换的 Sink；
- 被限制的 Source；
- 被切断的 Propagator；
- 其他未应用相同修复的同构路径。

Variant Search 应搜索同一个 Flow Pattern 的其他实例，文本相似只能作为候选召回手段。

## 通用性的边界

Flow-Based 适合以数据流、值流或资源流表达的漏洞，包括注入、路径、请求伪造、反序列化、文件访问、敏感数据泄露和部分内存大小传播问题。

它不能自然覆盖所有漏洞：

- 权限和认证逻辑错误；
- 业务状态机漏洞；
- TOCTOU 和并发竞争；
- 资源生命周期和 UAF；
- 复杂协议与密码学错误；
- 配置和部署错误。

因此当前方向应表述为 **通用 Flow-Based 漏洞研究引擎**，而不是“所有漏洞的统一模型”。未来如果加入 State-Transition、Authorization、Resource-Lifetime 等分析范式，应通过独立 change SPEC 与 Flow Model 并列，不能硬编码成伪 Source–Sink。

## 建议演进层级

```text
L1  Source/Sink 查询生成
L2  Source/Sink/Summary/Barrier 类型化 Flow IR
L3  断流诊断与模型补全
L4  Patch 驱动 Flow Delta 与变体发现
L5  多 Analyzer 编译与能力降级报告
L6  Model Pack 质量评估和持续治理
```

L1、L2 是基础能力；L3、L4 形成项目差异化；L5、L6 才能支撑较成熟的宿主无关漏洞研究平台。

## 当前阶段约束

在 `harden-workflow-commit-boundaries` 完成并 Verified 前，不应直接实施 Flow Model Core。当前工作流的提交、恢复和 artifact 一致性是未来 Flow 研究状态可依赖的基础。

后续应建立独立的 `introduce-flow-model-core` change SPEC，至少解决：

- Flow Model v1 的最小表达能力；
- `TaintQueryIntent` 的兼容转换；
- CodeQL Compiler 的能力边界；
- Probe、Connect、Diagnose、Revise 的状态机；
- 首批 Model Pack 范围；
- 与现有 Query Pack、verification level 和 replay 的兼容关系；
- 哪些功能属于宿主模型推理，哪些属于确定性 Core/Analyzer。

## 设计检查问题

后续每项 Flow-Based 设计都应回答：

1. 它描述的是漏洞流语义，还是在重复建设宿主 Agent？
2. 它是否独立于某条具体 CodeQL 查询？
3. 它能否表达 Source、Sink 之外的传播和阻断语义？
4. 无流时能否说明传播前沿和断流原因？
5. Analyzer 无法表达时是否明确报告能力损失？
6. 同一个模型能否用于 differential 和 variant 搜索？
7. 它是否把非 Flow 型漏洞错误地塞进 Source–Sink？

如果只能回答“把 YAML 转成 QL”，说明设计仍停留在包装层；如果能够稳定回答连接、断流、修订和变体问题，才体现 Flow-Based 漏洞研究引擎的价值。
