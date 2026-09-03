import type { DomainErrorRecord } from "@autovul/contracts";
import type { ApplicationApi } from "@autovul/core";

export interface DeepSeekFunctionDefinition {
  readonly type: "function";
  readonly function: {
    readonly name: string;
    readonly description: string;
    readonly parameters: Record<string, unknown>;
  };
}

export interface DeepSeekToolResult {
  readonly success: boolean;
  readonly output: string;
  readonly data?: unknown;
  readonly error?: DomainErrorRecord;
}

export interface DeepSeekHarnessPluginOptions {
  readonly cwd?: string;
  readonly runsDir?: string;
  readonly workspaceRoot?: string;
  readonly codeqlPath?: string;
  readonly timeoutMs?: number;
  readonly application?: ApplicationApi;
}

export interface DeepSeekHarnessPlugin {
  readonly tools: readonly DeepSeekFunctionDefinition[];
  readonly prompts: { readonly systemInstructions: string };
  execute(name: string, input: unknown, context?: { signal?: AbortSignal }): Promise<DeepSeekToolResult>;
  close(): Promise<void>;
}
