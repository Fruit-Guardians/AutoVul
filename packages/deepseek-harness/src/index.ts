import { createLocalApplication, readAutovulEnv } from "@autovul/codeql-runner";

import { DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS } from "./prompts.js";
import { DEEPSEEK_HARNESS_TOOLS, executeDeepSeekTool } from "./tools.js";
import type {
  DeepSeekHarnessPlugin,
  DeepSeekHarnessPluginOptions,
  DeepSeekToolResult,
} from "./types.js";

export function createDeepSeekHarnessPlugin(options: DeepSeekHarnessPluginOptions = {}): DeepSeekHarnessPlugin {
  const runsDir = options.runsDir ?? readAutovulEnv("RUNS_DIR");
  const codeqlPath = options.codeqlPath ?? process.env.CODEQL_PATH;
  const application = options.application ?? createLocalApplication({
    cwd: options.cwd ?? process.cwd(),
    ...(runsDir === undefined ? {} : { runsDir }),
    ...(options.workspaceRoot === undefined ? {} : { workspaceRoot: options.workspaceRoot }),
    ...(codeqlPath === undefined ? {} : { codeqlPath }),
    timeoutMs: options.timeoutMs ?? configuredTimeoutMs(),
  });

  return {
    tools: DEEPSEEK_HARNESS_TOOLS,
    prompts: {
      systemInstructions: DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS,
    },
    execute: (name: string, input: unknown, context?: { signal?: AbortSignal }): Promise<DeepSeekToolResult> => {
      return executeDeepSeekTool(application, name, input, context?.signal);
    },
    close: (): Promise<void> => {
      return application.close();
    },
  };
}

function configuredTimeoutMs(): number {
  const parsed = Number.parseInt(readAutovulEnv("TIMEOUT_MS") ?? "120000", 10);
  return Number.isFinite(parsed) && parsed >= 1_000 ? Math.min(parsed, 600_000) : 120_000;
}

export {
  DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS,
} from "./prompts.js";
export {
  DEEPSEEK_HARNESS_TOOLS,
  RESEARCH_TOOL_DEFINITION,
  RUN_TOOL_DEFINITION,
  executeDeepSeekTool,
} from "./tools.js";
export type {
  DeepSeekFunctionDefinition,
  DeepSeekHarnessPlugin,
  DeepSeekHarnessPluginOptions,
  DeepSeekToolResult,
} from "./types.js";
