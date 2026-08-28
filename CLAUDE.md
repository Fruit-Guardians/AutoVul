# AutoVul V2 — Claude 工作说明

@AGENTS.md

开始工作前完整阅读并遵守 [AGENTS.md](./AGENTS.md)。它是本项目定位、架构边界、证据标准和安全要求的事实源。

同时阅读并遵守 [SPEC.md](./SPEC.md)。涉及公开行为、契约、工作流、artifact、安全边界、Analyzer 或宿主集成的改动，必须先按 `specs/README.md` 建立并接受变更 SPEC，再开始实现。

## 必须保持的定位

AutoVul V2 **不是 Agent，也不是通用 Agent Harness**。它是面向漏洞研究的专业能力扩展，运行在 Pi Agent、DeepSeek Harness 等成熟宿主之下。

```text
宿主 Agent：模型、Agent Loop、上下文、计划、工具选择和用户交互
本项目：漏洞研究领域能力、确定性执行、证据、验证和可重放产物
```

不要在本项目中自行实现模型 Provider、通用 Agent Loop、长期记忆、上下文压缩、通用规划、子 Agent 编排，或宿主已经提供的通用文件/Shell/Web 能力。

## 修改代码时

- 先确定改动属于 Contracts、Core、Analyzer/Runner 还是 Integration。
- Core 不依赖 Pi、DeepSeek Harness、UI、具体模型或具体进程实现。
- Pi Extension、未来的 DeepSeek Plugin、MCP 和 CLI 必须保持为薄适配层。
- 新的漏洞研究能力应通过版本化契约、Core Port 和 Analyzer 实现，不要继续扩大单一 CodeQL workflow。
- 不把模型回答当作漏洞事实；结论必须由结构化、可重放的工具证据支持。
- 严格区分 `generated`、`compiled`、`reproduced`、`differential` 和 `variant_validated`。
- fake、mock 和诊断 wrapper 只能验证基础设施，不得作为真实漏洞成功证据。
- 真实环境不可用时明确报告阻塞或未运行，不得制造降级成功。
- 所有长任务要有 timeout、cancel、预算和子进程清理；所有状态要能从 artifact 恢复。
- 未经批准不要执行目标项目的安装、构建或其他高风险脚本。
- 保留用户已有修改，避免无关重构和破坏性 Git 操作。

## 推荐工作顺序

1. 阅读相关契约、Core 流程、Runner 和宿主适配。
2. 明确输入、输出、错误、证据和成功条件。
3. 先实现确定性领域逻辑，再实现工具适配，最后接入宿主。
4. 运行最小相关测试，再根据风险运行 `npm test`、类型检查和真实 Golden/replay。
5. 最终说明实际验证过什么、没有验证什么，以及产物位置。

任何方案在实施前都要先问：**这是在增强漏洞研究插件，还是在重复建设宿主 Agent？** 后者默认不属于本项目。
