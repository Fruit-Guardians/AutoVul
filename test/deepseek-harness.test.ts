import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";

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
        const fs = new NodeFileSystemPort();
        const vulnDir = join(dir, "vuln");
        const fixedDir = join(dir, "fixed");

        await fs.ensureDirectory(join(vulnDir, "src"));
        await fs.ensureDirectory(join(fixedDir, "src"));
        await fs.writeTextAtomic(join(vulnDir, "src/reporter.js"), vulnCode);
        await fs.writeTextAtomic(join(fixedDir, "src/reporter.js"), fixedCode);

        const jsAdapter = new JavascriptCfgMissingCheckAdapter({ filesystem: fs });
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
            vulnerable: { kind: "source_directory", path: vulnDir },
            fixed: { kind: "source_directory", path: fixedDir },
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

    it("normalizes validation and domain errors into structured failure records", async () => {
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

      // Malformed input payload
      const invalidPayload = await plugin.execute("autovul_research", { invalid: true });
      expect(invalidPayload.success).toBe(false);
      expect(invalidPayload.error?.code).toBe("INVALID_INPUT");

      await plugin.close();
    });
  });
});
