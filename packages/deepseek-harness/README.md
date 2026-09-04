# @autovul/deepseek-harness

`@autovul/deepseek-harness` provides a thin integration plugin for **DeepSeek Harness** and other OpenAI-compatible function-calling agents.

The adapter package is implemented and covered by repository tests. A real external DeepSeek Harness or official SDK acceptance run has not yet been recorded, so this package is not a verified native-host support claim.

## Host Boundary

- **DeepSeek Harness** owns LLM model configuration, context management, prompt engineering, and multi-turn loops.
- **Native audit first**: the host may inspect code and deliver a semantic audit conclusion without an AutoVul run. AutoVul and CodeQL remain optional escalation paths.
- **AutoVul Plugin** exposes OpenAI-compatible tool definitions, routes calls to `ApplicationApi`, and formats concise JSON responses.

## Exports

- `createDeepSeekHarnessPlugin(options)`: Factory creating a harness plugin instance wired to an `ApplicationApi`.
- `DEEPSEEK_HARNESS_TOOLS`: Ready-to-use OpenAI function-calling tool definitions for `autovul_research` and `autovul_run`.
- `DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS`: Reference system prompt snippet guiding models on hypothesis selection and parameter constraints.

## Usage Example

```typescript
import { createDeepSeekHarnessPlugin } from "@autovul/deepseek-harness";
import { createLocalApplication } from "@autovul/codeql-runner";

const app = createLocalApplication({ workspaceRoot: process.cwd() });
const plugin = createDeepSeekHarnessPlugin({ application: app });

// Pass to LLM API
const tools = plugin.tools;
const instructions = plugin.prompts.systemInstructions;

// When the model calls a tool:
const toolCallResult = await plugin.execute("autovul_research", {
  action: "execute",
  capability: "missing_check",
  hypothesis_version: "autovul.missing-check/1",
  hypothesis: { ... },
  mode: "differential",
  target: { ... },
});

console.log(toolCallResult.output); // Structured JSON returned to LLM
```
