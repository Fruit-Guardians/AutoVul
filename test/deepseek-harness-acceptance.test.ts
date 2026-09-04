import { describe, expect, it } from "vitest";
import { execFile as execFileCb } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";

import {
  type MissingCheckExecutionResult,
  type MissingCheckHypothesis,
  type RunManifest,
} from "@autovul/contracts";
import {
  createDeepSeekHarnessPlugin,
  type DeepSeekFunctionDefinition,
  type DeepSeekToolResult,
} from "../packages/deepseek-harness/src/index.js";

const execFile = promisify(execFileCb);
const root = resolve(import.meta.dirname, "..");

const hypothesis: MissingCheckHypothesis = {
  schema_version: "autovul.missing-check/1",
  hypothesis_id: "mcheck-openclaw-43572-deepseek",
  language: "javascript",
  operation: { kind: "direct_call", name: "handleSigninTokenExchangeInvoke" },
  required_check: { kind: "direct_call", name: "isSigninInvokeAuthorized" },
  required_relation: "same_callback_cfg_dominates_operation",
  scope: {
    kind: "single_file_named_entry_cfg",
    file: "extensions/msteams/src/monitor-handler.ts",
    entry: { kind: "named_function", name: "registerMSTeamsHandlers" },
  },
};

const openclawVulnCode = `
export function registerMSTeamsHandlers(app) {
  const result = handleSigninTokenExchangeInvoke(app);
  return result;
}
`;

const openclawFixedCode = `
export function registerMSTeamsHandlers(app) {
  if (!isSigninInvokeAuthorized(app)) {
    return null;
  }
  const result = handleSigninTokenExchangeInvoke(app);
  return result;
}
`;

async function runGit(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFile("git", args, { cwd, encoding: "utf8" });
  return stdout.trim();
}

async function createGitRepo(
  dir: string,
  commits: { message: string; files: Record<string, string> }[],
): Promise<string[]> {
  await runGit(dir, ["init", "--initial-branch=main"]);
  await runGit(dir, ["config", "user.email", "test@example.invalid"]);
  await runGit(dir, ["config", "user.name", "Test"]);

  const oids: string[] = [];
  for (const c of commits) {
    for (const [relPath, content] of Object.entries(c.files)) {
      const fullPath = join(dir, relPath);
      await mkdir(dirname(fullPath), { recursive: true });
      await writeFile(fullPath, content, "utf8");
      await runGit(dir, ["add", relPath]);
    }
    await runGit(dir, ["commit", "-m", c.message]);
    const oid = await runGit(dir, ["rev-parse", "HEAD"]);
    oids.push(oid);
  }
  return oids;
}

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "autovul-deepseek-acceptance-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

interface DeepSeekMessage {
  role: "system" | "user" | "assistant" | "tool";
  content?: string;
  tool_calls?: {
    id: string;
    type: "function";
    function: {
      name: string;
      arguments: string;
    };
  }[];
  tool_call_id?: string;
}

/**
 * DeepSeek Harness Host Loop Fixture
 * Emulates the OpenAI / DeepSeek function calling protocol over createDeepSeekHarnessPlugin.
 */
class DeepSeekHarnessHostFixture {
  readonly conversation: DeepSeekMessage[] = [];
  private callCounter = 0;

  constructor(
    readonly tools: readonly DeepSeekFunctionDefinition[],
    systemPrompt: string,
    private readonly dispatcher: (name: string, input: unknown, signal?: AbortSignal) => Promise<DeepSeekToolResult>,
  ) {
    this.conversation.push({ role: "system", content: systemPrompt });
  }

  addUserMessage(content: string): void {
    this.conversation.push({ role: "user", content });
  }

  async executeToolCall(name: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<DeepSeekToolResult> {
    this.callCounter += 1;
    const callId = `call_${this.callCounter.toString().padStart(4, "0")}`;
    const argsJson = JSON.stringify(args);

    this.conversation.push({
      role: "assistant",
      tool_calls: [
        {
          id: callId,
          type: "function",
          function: { name, arguments: argsJson },
        },
      ],
    });

    const result = await this.dispatcher(name, args, signal);

    this.conversation.push({
      role: "tool",
      tool_call_id: callId,
      content: result.output,
    });

    return result;
  }
}

describe("DeepSeek Harness External Boundary Acceptance (REQ-DSEEK-009)", () => {
  it("executes full audit trajectory across registration, research, status, replay, invalid-input, cancellation, and shutdown", async () => {
    await withTempDir(async (dir) => {
      const repoDir = join(dir, "repo");
      await mkdir(repoDir, { recursive: true });

      const [vulnOid, fixedOid] = await createGitRepo(repoDir, [
        {
          message: "vulnerable: token exchange invoke without authorization check",
          files: { "extensions/msteams/src/monitor-handler.ts": openclawVulnCode },
        },
        {
          message: "fixed: add isSigninInvokeAuthorized guard check",
          files: { "extensions/msteams/src/monitor-handler.ts": openclawFixedCode },
        },
      ]);

      // Uses production factory createLocalApplication implicitly!
      const plugin = createDeepSeekHarnessPlugin({
        cwd: repoDir,
        workspaceRoot: repoDir,
        runsDir: join(dir, "runs"),
      });

      const host = new DeepSeekHarnessHostFixture(
        plugin.tools,
        plugin.prompts.systemInstructions,
        (name, input, signal) => plugin.execute(name, input, signal === undefined ? {} : { signal }),
      );

      // Verify tool registration conforms to OpenAI/DeepSeek function-calling schema
      expect(plugin.tools).toHaveLength(2);
      expect(plugin.tools.map((t) => t.function.name)).toEqual(["autovul_research", "autovul_run"]);
      for (const tool of plugin.tools) {
        expect(tool.type).toBe("function");
        expect(tool.function.name).toBeTruthy();
        expect(tool.function.description).toBeTruthy();
        expect(tool.function.parameters).toBeDefined();
      }

      // Turn 1: User requests patch audit, Model calls autovul_research in differential mode
      host.addUserMessage("Audit OpenClaw CVE-2026-43572 using patch-guided differential verification");
      const researchResult = await host.executeToolCall("autovul_research", {
        action: "execute",
        capability: "missing_check",
        hypothesis_version: "autovul.missing-check/1",
        hypothesis,
        analyzer_id: "javascript_cfg",
        mode: "differential",
        target: {
          vulnerable: { kind: "git_revision", repository: repoDir, revision: vulnOid },
          fixed: { kind: "git_revision", repository: repoDir, revision: fixedOid },
        },
        budget: { timeout_ms: 15_000 },
        idempotency_key: "deepseek-acceptance-case-01",
      });

      expect(researchResult.success).toBe(true);
      const researchData = researchResult.data as MissingCheckExecutionResult;
      expect(researchData.verification_level).toBe("differential");
      expect(researchData.decision.outcome).toBe("check_missing");
      expect(researchData.decision.fixed_outcome).toBe("check_present");
      expect(researchData.decision.fixed_policy_satisfied).toBe(true);
      const runId = researchData.run_id;

      // Turn 2: Inspect run status via autovul_run
      const statusResult = await host.executeToolCall("autovul_run", {
        action: "status",
        run_id: runId,
      });

      expect(statusResult.success).toBe(true);
      const statusData = statusResult.data as RunManifest;
      expect(statusData.status).toBe("completed");
      expect(statusData.verificationLevel).toBe("differential");

      // Turn 3: Execute model-free replay via autovul_run
      const replayResult = await host.executeToolCall("autovul_run", {
        action: "replay",
        run_id: runId,
      });

      expect(replayResult.success).toBe(true);
      const replayData = replayResult.data as MissingCheckExecutionResult;
      expect(replayData.verification_level).toBe("differential");
      expect(replayData.decision.outcome).toBe("check_missing");
      expect(replayData.decision.fixed_outcome).toBe("check_present");

      // Turn 4: Structured invalid input handled cleanly without process crash
      const invalidInputResult = await host.executeToolCall("autovul_research", {
        action: "execute",
        capability: "missing_check",
        // missing hypothesis, mode, target, budget
      });

      expect(invalidInputResult.success).toBe(false);
      expect(invalidInputResult.error?.code).toBe("INVALID_INPUT");
      expect(JSON.parse(invalidInputResult.output)).toHaveProperty("error");

      // Turn 5: Operation cancellation via AbortSignal
      const controller = new AbortController();
      controller.abort();
      const cancelledResult = await host.executeToolCall("autovul_research", {
        action: "execute",
        capability: "missing_check",
        hypothesis_version: "autovul.missing-check/1",
        hypothesis,
        analyzer_id: "javascript_cfg",
        mode: "differential",
        target: {
          vulnerable: { kind: "git_revision", repository: repoDir, revision: vulnOid },
          fixed: { kind: "git_revision", repository: repoDir, revision: fixedOid },
        },
        budget: { timeout_ms: 15_000 },
        idempotency_key: "deepseek-cancelled-run",
      }, controller.signal);

      expect(cancelledResult.success).toBe(false);
      expect(["PROCESS_CANCELLED", "MCHECK_EXECUTION_CANCELLED"]).toContain(cancelledResult.error?.code);

      // Turn 6: Shutdown lifecycle management
      await plugin.close();

      // Turn 7: Post-close tool invocation fails gracefully with structured domain error
      const postCloseResult = await host.executeToolCall("autovul_run", {
        action: "status",
        run_id: runId,
      });

      expect(postCloseResult.success).toBe(false);
      expect(postCloseResult.error?.code).toBe("INVALID_STATE_TRANSITION");

      // Save acceptance transcript as immutable verification evidence
      const transcriptPath = join(root, "specs/changes/add-deepseek-harness-integration/evidence/acceptance-transcript.json");
      await writeFile(
        transcriptPath,
        JSON.stringify(
          {
            harness: "DeepSeek Function Calling Protocol Fixture",
            timestamp: new Date().toISOString(),
            turns: host.conversation.length,
            trajectory: host.conversation,
          },
          null,
          2,
        ),
        "utf8",
      );
    });
  });
});
