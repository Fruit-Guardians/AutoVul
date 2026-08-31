# AutoVul V2 项目章程

## 项目定位

AutoVul V2 是一个**面向成熟 Agent/Harness 的漏洞研究能力层与确定性执行系统**。

本项目不实现 Agent，也不实现通用 Agent Harness。它依附于 Pi Agent、DeepSeek Harness 等成熟宿主，以 Extension、Plugin、MCP 或稳定 API 的形式，为宿主提供可组合、可验证、可重放的漏洞研究能力。

一句话边界：

> 宿主 Agent 负责理解、推理和编排；AutoVul 负责漏洞研究能力、确定性执行、证据固化和结果验证。

“通用”在本项目中表示**宿主无关、语言与分析器可扩展、能够支持多类漏洞研究流程**，不表示建设通用 Coding Agent。

## 宿主与本项目的职责

### 宿主 Agent 负责

- 模型接入、Agent Loop、会话和上下文管理。
- 阅读用户请求，理解漏洞描述、补丁和源码。
- 制定研究计划、选择工具、根据诊断进行推理和修订。
- 使用宿主已有的文件、Shell、Git、Web、搜索、记忆和子 Agent 能力。
- 向用户发起必要的审批和交互，并负责最终自然语言表达。

### AutoVul 负责

- 定义版本化的漏洞研究输入、假设、证据、发现和验证契约。
- 暴露少量、稳定、结构化的安全研究工具。
- 执行 CodeQL 等分析器的探测、编译、运行、诊断和验证。
- 管理阶段状态、预算、超时、取消、并发锁、checkpoint 和恢复。
- 保存结构化诊断、运行轨迹、证据、结果和可重放产物。
- 对漏洞版本、修复版本、正负样本执行确定性验证。
- 为 Pi、DeepSeek Harness、MCP、CLI 和未来宿主提供薄适配层。

## 明确的非目标

除非项目方向被正式修改，否则不要在本项目中建设：

- 自有 LLM Provider 框架或通用模型路由层。
- 自有通用 Agent Loop、对话系统、长期记忆或上下文压缩。
- 通用计划、目标、任务队列或子 Agent 编排框架。
- 通用 Coding Agent 的文件编辑、Shell、浏览器和 Web 搜索替代品。
- 与 Pi Agent、DeepSeek Harness 等宿主竞争的终端或桌面 Agent 产品。
- 缺少证据约束的通用安全聊天助手。

确定性 CLI 可以用于调试、CI、重放和无模型验证，但不应逐步演变为另一个独立 Agent。

## 产品方向

当前 CodeQL 查询合成与验证链路是第一个已实现能力，不是整个产品边界。长期方向是宿主无关、研究语义可并列的漏洞研究能力层，例如：

- CodeQL 查询合成、断流诊断与差分验证。
- 漏洞描述、补丁与提交历史分析。
- Source、Sink、Sanitizer、Barrier 和缺失流模型识别。
- 依赖和供应链漏洞研究。
- 静态分析器、模糊测试器和动态复现器的统一接入。
- 漏洞假设、证据链、复现结论和版本化、可验证的机器契约。
- 跨项目变体发现与误报/漏报验证。

新增能力应以领域能力、Analyzer 或 Integration 的形式进入，不应塞进一个不断扩张的 CodeQL 工作流。Flow、MissingCheck、Typestate 等研究范式可以共享运行、预算、证据和 replay 底座，但必须分别定义假设结构、观察语义和成功谓词。不要建设把所有漏洞改写成 Source–Sink 的万能 IR，也不要在第二种真实范式出现前设计通用漏洞本体。

Core 面向宿主返回结构化观察、裁决、修订提示和 artifact 引用，不撰写 WP、审计报告或面向人的 Finding 叙事。最终自然语言表达属于宿主。

## 架构边界

推荐保持以下逻辑分层：

```text
Host Agent / Harness
  └─ Integration Adapter
       └─ Vulnerability Research Core
            ├─ Research Capabilities
            │    ├─ Flow（当前）
            │    └─ Future Capability（case-gated）
            ├─ Shared Runtime and Evidence
            └─ Capability-specific Analyzer Ports
                 ├─ CodeQL
                 ├─ Patch / Git
                 ├─ Dependency Intelligence
                 ├─ Static Analysis
                 └─ Dynamic Reproduction
```

当前包的强制依赖方向继续成立：

```text
contracts <- core <- codeql-runner <- pi-extension / cli
```

开发时遵守以下规则：

1. `contracts` 只保存版本化 Schema、类型和稳定协议，不依赖宿主、UI、进程或具体分析器实现。
2. `core` 保存领域规则、工作流、预算、状态转换和验收逻辑；通过 Ports 使用外部能力。
3. Analyzer/Runner 负责具体工具协议、命令执行和输出解码，不决定产品层面的成功标准。
4. Pi Extension、DeepSeek Plugin、MCP 和 CLI 都是薄适配层，不复制领域工作流。
5. 宿主专属类型、Prompt、UI 和生命周期逻辑不得泄漏进 Core。
6. 不要因为某个宿主暂时缺少能力，就把一套通用 Agent 基础设施复制进项目。
7. 新宿主应适配同一个 Application API 和版本化契约，而不是形成独立实现。
8. 共享 Runtime 只管理运行、预算、取消、锁、恢复、证据和 replay，不解释 Capability 的领域字段。
9. 每个 Capability 单独拥有 Hypothesis、Observation、Decision Policy、诊断码和真实验收门。

## 漏洞研究的事实标准

模型输出是研究假设，不是事实。成功声明必须来自工具产生的结构化证据。

结果等级必须严格区分：

- `generated`：只生成了候选，尚未通过执行验证。
- `compiled`：分析规则编译通过，但尚未证明漏洞存在。
- `reproduced`：在目标漏洞版本中命中预期位置或行为。
- `differential`：漏洞版本命中，修复版本不命中。
- `variant_validated`：通过额外正样本、负样本或跨项目变体验证。

不得把以下情况描述为已确认漏洞或成功规则：

- 只有模型推理或自然语言判断。
- 只有 Source/Sink probe 命中，没有端到端 flow。
- 只有编译成功，没有目标结果。
- fixed 数据库仍然命中，但未解释为预期行为。
- fake runner、mock、诊断 wrapper 或参考查询泄漏产生的成功。
- 因超时、环境缺失或解析失败而没有完成验证。

失败和负结果也是研究证据，必须保留原始阶段、诊断类别、重试条件和可复现输入。

## 安全与可靠性原则

- 所有长时间操作必须支持超时和取消，并清理完整子进程树。
- 文件写入采用原子方式；运行状态必须可恢复，不能依赖宿主会话作为唯一事实源。
- 路径必须规范化并受 workspace/trusted-root 边界约束，防止 symlink escape。
- 不自动执行未经批准的目标项目构建脚本、安装脚本或其他高风险命令。
- 输出、日志、trace 和 artifact 不得保存已识别的密钥或敏感环境变量。
- 重试必须基于结构化、可重试的错误分类；不要对语法错误、策略拒绝和错误研究假设盲目重试。
- 候选数量、修订次数、执行时间、输出大小和并发必须有明确预算。
- 验收以真实工具执行、真实 vulnerable/fixed 结果和独立 replay 为准。

## 面向宿主的接口原则

- 工具数量保持少而稳定，优先提供领域聚合工具，避免向模型暴露大量底层命令。
- 工具输入输出使用严格、版本化 Schema；自然语言说明不能替代结构化字段。
- 返回紧凑的模型可消费摘要，同时把完整证据写入 artifact。
- 诊断必须告诉宿主下一步可以修复什么，但不能伪造修复结论。
- 模型可见结果中的每个业务字段必须支持路由、修订、执行、验证、replay 或停止；其余内容进入 artifact。
- 校验错误优先返回稳定 `code`、字段 `path` 和必要的 `allowed_values`，不得用散文代替结构化约束。
- Core 可以返回结构化 revision hint 和允许的后续动作，但不得生成下一份完整假设或自行循环。
- 宿主中断、切换模型或压缩上下文后，能够通过 run id 和 artifact 恢复。
- 宿主集成只负责注册、参数转换、UI 和生命周期装配。

## 代码修改准则

修改前先判断需求属于哪一层：

- 模型推理、计划、会话、上下文、通用工具：应由宿主解决。
- 漏洞研究语义、证据、验证、预算和状态：属于 Core/Contracts。
- CodeQL CLI/LSP 或其他分析工具的调用：属于 Analyzer/Runner。
- Pi、DeepSeek Harness、MCP、CLI 的注册与呈现：属于 Integration。

实现新功能时：

1. 先定义领域输入、输出、错误和证据契约。
2. 再在 Core 中定义确定性规则和 Port。
3. 在 Runner/Analyzer 中实现外部工具适配。
4. 最后添加宿主适配，且不得复制 Core 逻辑。
5. 使用 fake adapter 做状态和故障测试，使用真实分析器做 Golden 和 replay 验收。
6. 保留现有用户改动；不要为无关问题进行破坏性清理。

## SPEC 驱动规则

[SPEC.md](./SPEC.md) 是产品行为、边界和验收要求的规范事实源。`AGENTS.md` 规定协作与工程原则，`SPEC.md` 规定系统必须做什么；实现代码、测试、README 和宿主提示词都不得与已接受的 SPEC 冲突。

### 规则优先级

1. 安全边界与用户当前的明确指令。
2. 已接受的 `SPEC.md` 和 `specs/changes/` 变更规范。
3. 本 `AGENTS.md` 的架构与工程约束。
4. README、计划文档、注释和当前实现。

如果用户要求与已接受 SPEC 冲突，不要静默修改代码绕过规范。先指出冲突并更新或新增变更 SPEC；用户明确批准该变更后再实施。

### 何时必须先写变更 SPEC

以下改动在实现前必须建立 `specs/changes/<change-id>/SPEC.md`：

- 新增或改变用户可观察行为、工作流阶段或成功标准。
- 修改公开 Schema、Application API、工具输入输出或 artifact 格式。
- 新增 Analyzer、宿主集成、验证等级或漏洞研究能力。
- 改变权限、trusted root、命令执行、审批、数据保留或其他安全边界。
- 改变超时、取消、预算、重试、并发、锁或恢复语义。
- 声明新增语言、平台、分析器或真实漏洞研究能力支持。

纯文档勘误、只补充已有行为的测试、无行为变化的局部重构和完全由现有 SPEC 明确定义的缺陷修复，可以不建立独立变更 SPEC。若实现暴露出规范歧义，仍应先补齐 SPEC。

### SPEC 生命周期

1. **Draft**：描述问题、范围、非目标、行为、契约、风险和验收标准。
2. **Accepted**：由用户或维护者明确批准；未批准的 Draft 不能作为扩大范围的授权。
3. **Implemented**：代码和迁移完成，但不能据此声称验证成功。
4. **Verified**：所有要求均有对应测试或真实证据，未运行项明确记录。
5. **Archived**：将稳定行为合并回根 `SPEC.md`，变更记录保留用于追溯。

### SPEC 内容要求

- 使用 `MUST`、`MUST NOT`、`SHOULD`、`MAY` 表达约束强度。
- 每项可验收要求使用稳定编号，例如 `REQ-CORE-001`。
- 验收标准必须可观察，优先使用 Given/When/Then 或明确输入/输出。
- 明确非目标、兼容性、失败模式、安全影响和迁移策略。
- 区分 fake/infrastructure test 与真实 Analyzer、Golden、differential、replay 证据。
- 每项要求必须能够追踪到测试、检查命令或人工验证证据。

实现完成后，逐项核对 SPEC，不得用“测试通过”替代需求追踪，也不得通过放宽 SPEC 或 Golden 条件掩盖实现失败。

## 当前开发与验证

V2 是 TypeScript workspace。常用检查：

```bash
npm run build
npm run typecheck
npm test
npm run lint
npm run pack:check
```

真实 CodeQL、真实模型和 Golden 测试可能需要额外环境。缺少依赖时必须报告为 `BLOCKED` 或未运行，不能回退成假成功。

## 决策检查

每个重要设计都应能够回答：

1. 这是漏洞研究能力，还是在重复建设宿主 Agent？
2. 这项能力是否能被 Pi 和 DeepSeek Harness 等不同宿主复用？
3. 结论是否由可重放证据支持？
4. 失败、中断和环境缺失是否能被准确恢复和表达？
5. 新增代码是否放在正确层，并保持 Integration 足够薄？

如果第一问的答案是“通用 Agent 能力”，默认停止实现并交给宿主；如果后三问不能明确回答，功能尚未达到合入标准。
