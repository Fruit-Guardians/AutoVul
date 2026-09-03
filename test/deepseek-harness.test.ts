import { describe, expect, it } from "vitest";
import { execFile as execFileCb } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

import {
  type MissingCheckExecutionResult,
  type MissingCheckHypothesis,
} from "@autovul/contracts";
import {
  Application,
  CompositeMissingCheckExecutionPort,
} from "@autovul/core";
import {
  JavascriptCfgMissingCheckAdapter,
  NodeFileSystemPort,
} from "@autovul/codeql-runner";
import {
  createDeepSeekHarnessPlugin,
  DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS,
  DEEPSEEK_HARNESS_TOOLS,
} from "../packages/deepseek-harness/src/index.js";
import {
  FakeCodeqlPort,
  FixedClock,
  FixedIdGenerator,
  MemoryArtifactStore,
} from "./helpers.js";

const execFile = promisify(execFileCb);

const hypothesis: MissingCheckHypothesis = {
  schema_version: "autovul.missing-check/1",
  hypothesis_id: "mcheck-deepseek-test",
  language: "javascript",
  operation: { kind: "direct_call", name: "sendSensitiveReport" },
  required_check: { kind: "direct_call", name: "assertPermission" },
  required_relation: "same_callback_cfg_dominates_operation",
  scope: {
    kind: "single_file_named_entry_cfg",
    file: "src/reporter.js",
    entry: { kind: "named_function", name: "handleReportRequest" },
  },
};

const vulnCode = `
export function handleReportRequest(user) {
  sendSensitiveReport(user);
}
`;

const fixedCode = `
export function handleReportRequest(user) {
  if (!assertPermission(user)) {
    return;
  }
  sendSensitiveReport(user);
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

async function withTempDirectory<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "autovul-deepseek-test-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe("DeepSeek Harness Integration Adapter (@autovul/deepseek-harness)", () => {
  describe("Tool Declarations and Prompts", () => {
    it("exposes standard OpenAI/DeepSeek function definitions", () => {
      expect(DEEPSEEK_HARNESS_TOOLS).toHaveLength(2);
      const toolNames = DEEPSEEK_HARNESS_TOOLS.map((t) => t.function.name);
      expect(toolNames).toContain("autovul_research");
      expect(toolNames).toContain("autovul_run");

      for (const tool of DEEPSEEK_HARNESS_TOOLS) {
        expect(tool.type).toBe("function");
        expect(tool.function.name).toBeTruthy();
        expect(tool.function.description).toBeTruthy();
        expect(tool.function.parameters).toBeDefined();
      }
    });

    it("provides system prompt instructions for host agent", () => {
      expect(DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS).toContain("autovul_research");
      expect(DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS).toContain("autovul_run");
      expect(DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS).toContain("missing_check");
      expect(DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS).toContain("flow");
      expect(DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS).toContain("typestate");
      expect(DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS).toContain("git_revision");
    });
  });

  describe("Plugin Execution via ApplicationApi", () => {
    it("executes autovul_research validate action cleanly", async () => {
      const plugin = createDeepSeekHarnessPlugin({
        application: new Application({
          codeql: new FakeCodeqlPort(),
          artifacts: new MemoryArtifactStore(),
          clock: new FixedClock(1_700_000_000_000),
          ids: new FixedIdGenerator(["run-1"]),
        }),
      });

      const result = await plugin.execute("autovul_research", {
        action: "validate",
        capability: "missing_check",
        hypothesis_version: "autovul.missing-check/1",
        hypothesis,
      });

      expect(result.success).toBe(true);
      expect(result.data).toEqual(expect.objectContaining({ valid: true }));
      await plugin.close();
    });

    it("executes differential research and replay through the DeepSeek Harness plugin", async () => {
      await withTempDirectory(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });

        const [vulnOid, fixedOid] = await createGitRepo(repoDir, [
          {
            message: "vulnerable report handler",
            files: { "src/reporter.js": vulnCode },
          },
          {
            message: "fixed report handler with authorization",
            files: { "src/reporter.js": fixedCode },
          },
        ]);

        const fs = new NodeFileSystemPort();
        const jsAdapter = new JavascriptCfgMissingCheckAdapter({
          trustedRoots: [repoDir],
          filesystem: fs,
        });
        const missingCheck = new CompositeMissingCheckExecutionPort({
          javascript_cfg: jsAdapter,
        });

        const app = new Application({
          codeql: new FakeCodeqlPort(),
          artifacts: new MemoryArtifactStore(join(dir, "runs")),
          clock: new FixedClock(1_700_000_000_000),
          ids: new FixedIdGenerator(["run-deepseek-diff-1"]),
          missingCheck,
        });

        const plugin = createDeepSeekHarnessPlugin({ application: app });

        const researchResult = await plugin.execute("autovul_research", {
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
          budget: { timeout_ms: 5_000 },
          idempotency_key: "deepseek-mcheck-key",
        });

        expect(researchResult.success).toBe(true);
        const data = researchResult.data as MissingCheckExecutionResult;
        expect(data.verification_level).toBe("differential");
        expect(data.decision.outcome).toBe("check_missing");
        expect(data.decision.fixed_outcome).toBe("check_present");

        // Execute replay via autovul_run
        const replayResult = await plugin.execute("autovul_run", {
          action: "replay",
          run_id: data.run_id,
        });

        expect(replayResult.success).toBe(true);
        const replayData = replayResult.data as MissingCheckExecutionResult;
        expect(replayData.verification_level).toBe("differential");
        expect(replayData.decision.outcome).toBe("check_missing");

        // Inspect status via autovul_run
        const statusResult = await plugin.execute("autovul_run", {
          action: "status",
          run_id: data.run_id,
        });
        expect(statusResult.success).toBe(true);

        await plugin.close();
      });
    });

    it("normalizes validation and domain errors into structured failure JSON output", async () => {
      const plugin = createDeepSeekHarnessPlugin({
        application: new Application({
          codeql: new FakeCodeqlPort(),
          artifacts: new MemoryArtifactStore(),
          clock: new FixedClock(1_700_000_000_000),
          ids: new FixedIdGenerator(["run-err"]),
        }),
      });

      // Unknown tool name
      const unknownTool = await plugin.execute("unknown_harness_tool", {});
      expect(unknownTool.success).toBe(false);
      expect(unknownTool.error?.code).toBe("INVALID_INPUT");
      expect(JSON.parse(unknownTool.output)).toEqual({ error: unknownTool.error });

      // Malformed input payload
      const invalidPayload = await plugin.execute("autovul_research", { invalid: true });
      expect(invalidPayload.success).toBe(false);
      expect(invalidPayload.error?.code).toBe("INVALID_INPUT");
      expect(JSON.parse(invalidPayload.output)).toEqual({ error: invalidPayload.error });

      await plugin.close();
    });
  });
});
