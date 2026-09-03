import {
  asDomainError,
  AutovulResearchToolInputSchema,
  AutovulRunToolInputSchema,
  DomainError,
  parseSchema,
} from "@autovul/contracts";
import type { ApplicationApi } from "@autovul/core";

import type { DeepSeekFunctionDefinition, DeepSeekToolResult } from "./types.js";

export const RESEARCH_TOOL_DEFINITION: DeepSeekFunctionDefinition = {
  type: "function",
  function: {
    name: "autovul_research",
    description: "Validate or execute a versioned Flow, MissingCheck, or Typestate vulnerability research hypothesis, or execute the Change Observation static service.",
    parameters: AutovulResearchToolInputSchema as unknown as Record<string, unknown>,
  },
};

export const RUN_TOOL_DEFINITION: DeepSeekFunctionDefinition = {
  type: "function",
  function: {
    name: "autovul_run",
    description: "Inspect, cancel, or replay a bounded AutoVul research operation through the shared deterministic runtime.",
    parameters: AutovulRunToolInputSchema as unknown as Record<string, unknown>,
  },
};

export const DEEPSEEK_HARNESS_TOOLS: readonly DeepSeekFunctionDefinition[] = [
  RESEARCH_TOOL_DEFINITION,
  RUN_TOOL_DEFINITION,
];

export async function executeDeepSeekTool(
  application: ApplicationApi,
  name: string,
  input: unknown,
  signal?: AbortSignal,
): Promise<DeepSeekToolResult> {
  try {
    if (name === "autovul_research") {
      const params = parseSchema(AutovulResearchToolInputSchema, input, "autovul_research input");
      const result = await application.research(params, signal === undefined ? {} : { signal });
      return {
        success: true,
        output: JSON.stringify(result, null, 2),
        data: result,
      };
    }

    if (name === "autovul_run") {
      const params = parseSchema(AutovulRunToolInputSchema, input, "autovul_run input");
      const result = await application.manageRun(params, signal === undefined ? {} : { signal });
      return {
        success: true,
        output: JSON.stringify(result, null, 2),
        data: result,
      };
    }

    throw new DomainError("INVALID_INPUT", "input", `Unsupported DeepSeek Harness tool: ${name}`, false, { name });
  } catch (error: unknown) {
    const domain = asDomainError(error);
    return {
      success: false,
      output: domain.message,
      error: domain.toRecord(),
    };
  }
}
