import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";

import {
  DomainError,
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
  FakeCodeqlPort,
  FixedClock,
  FixedIdGenerator,
  MemoryArtifactStore,
} from "./helpers.js";

const hypothesis: MissingCheckHypothesis = {
  schema_version: "autovul.missing-check/1",
  hypothesis_id: "mcheck-msteams-cfg",
  language: "javascript",
  operation: { kind: "direct_call", name: "handleSigninTokenExchangeInvoke" },
  required_check: { kind: "direct_call", name: "isSigninInvokeAuthorized" },
  required_relation: "same_callback_cfg_dominates_operation",
  scope: {
    kind: "single_file_named_entry_cfg",
    file: "src/handler.js",
    entry: { kind: "named_function", name: "registerMSTeamsHandlers" },
  },
};

const vulnerableCode = `
export function registerMSTeamsHandlers(app) {
  const result = handleSigninTokenExchangeInvoke();
  return result;
}
`;

const fixedCodeWithGuard = `
export function registerMSTeamsHandlers(app) {
  if (!isSigninInvokeAuthorized()) {
    return null;
  }
  const result = handleSigninTokenExchangeInvoke();
  return result;
}
`;

const fixedCodeWithIfBranch = `
export function registerMSTeamsHandlers(app) {
  if (isSigninInvokeAuthorized()) {
    return handleSigninTokenExchangeInvoke();
  }
  return null;
}
`;

const bypassCode = `
export function registerMSTeamsHandlers(app, isDev) {
  if (isDev) {
    return handleSigninTokenExchangeInvoke();
  }
  if (isSigninInvokeAuthorized()) {
    return handleSigninTokenExchangeInvoke();
  }
  return null;
}
`;

async function withTempDirectory<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "autovul-js-cfg-test-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe("MissingCheck JavaScript CFG Analyzer v1", () => {
  describe("Direct Adapter Intra-procedural CFG Analysis", () => {
    it("identifies unchecked witness when operation is called without check (vulnerable)", async () => {
      await withTempDirectory(async (dir) => {
        const fs = new NodeFileSystemPort();
        await fs.ensureDirectory(join(dir, "src"));
        await fs.writeTextAtomic(join(dir, "src/handler.js"), vulnerableCode);

        const adapter = new JavascriptCfgMissingCheckAdapter({ filesystem: fs });
        const observation = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "source_directory", path: dir } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run_test_vulnerable",
          artifactRoot: join(dir, "runs"),
        }, { timeoutMs: 5_000 });

        expect(observation.compile_accepted).toBe(true);
        expect(observation.analyzer.analyzer_id).toBe("javascript_cfg");
        expect(observation.analyzer.evidence_kind).toBe("real_analyzer");
        expect(observation.operation.state).toBe("observed");
        expect(observation.operation.locations).toEqual([{ file: "src/handler.js", start_line: 3 }]);
        expect(observation.required_check.state).toBe("not_found");
        expect(observation.relation.state).toBe("unchecked_witness");
        expect(observation.relation.unchecked_witnesses).toHaveLength(1);
        expect(observation.relation.unchecked_witnesses[0].operation.start_line).toBe(3);
        expect(observation.relation.checked_witnesses).toHaveLength(0);
      });
    });

    it("identifies checked witness when operation is guarded by return check (fixed)", async () => {
      await withTempDirectory(async (dir) => {
        const fs = new NodeFileSystemPort();
        await fs.ensureDirectory(join(dir, "src"));
        await fs.writeTextAtomic(join(dir, "src/handler.js"), fixedCodeWithGuard);

        const adapter = new JavascriptCfgMissingCheckAdapter({ filesystem: fs });
        const observation = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "source_directory", path: dir } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run_test_fixed_guard",
          artifactRoot: join(dir, "runs"),
        }, { timeoutMs: 5_000 });

        expect(observation.compile_accepted).toBe(true);
        expect(observation.operation.state).toBe("observed");
        expect(observation.required_check.state).toBe("observed");
        expect(observation.relation.state).toBe("checked_witness");
        expect(observation.relation.checked_witnesses).toHaveLength(1);
        expect(observation.relation.unchecked_witnesses).toHaveLength(0);
      });
    });

    it("identifies checked witness when operation is inside if(check()) branch", async () => {
      await withTempDirectory(async (dir) => {
        const fs = new NodeFileSystemPort();
        await fs.ensureDirectory(join(dir, "src"));
        await fs.writeTextAtomic(join(dir, "src/handler.js"), fixedCodeWithIfBranch);

        const adapter = new JavascriptCfgMissingCheckAdapter({ filesystem: fs });
        const observation = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "source_directory", path: dir } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run_test_fixed_branch",
          artifactRoot: join(dir, "runs"),
        }, { timeoutMs: 5_000 });

        expect(observation.relation.state).toBe("checked_witness");
        expect(observation.relation.checked_witnesses).toHaveLength(1);
        expect(observation.relation.unchecked_witnesses).toHaveLength(0);
      });
    });

    it("identifies unchecked witness when a bypass path exists", async () => {
      await withTempDirectory(async (dir) => {
        const fs = new NodeFileSystemPort();
        await fs.ensureDirectory(join(dir, "src"));
        await fs.writeTextAtomic(join(dir, "src/handler.js"), bypassCode);

        const adapter = new JavascriptCfgMissingCheckAdapter({ filesystem: fs });
        const observation = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "source_directory", path: dir } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run_test_bypass",
          artifactRoot: join(dir, "runs"),
        }, { timeoutMs: 5_000 });

        expect(observation.relation.state).toBe("unchecked_witness");
        expect(observation.relation.unchecked_witnesses).toHaveLength(1);
        expect(observation.relation.checked_witnesses).toHaveLength(1);
      });
    });
  });

  describe("Target Fingerprinting for Source Directories", () => {
    it("computes deterministic fingerprint for source directory", async () => {
      await withTempDirectory(async (dir) => {
        const fs = new NodeFileSystemPort();
        await fs.ensureDirectory(join(dir, "src"));
        await fs.writeTextAtomic(join(dir, "src/handler.js"), vulnerableCode);

        const adapter = new JavascriptCfgMissingCheckAdapter({ filesystem: fs });
        const fp1 = await adapter.validateTarget({ kind: "source_directory", path: dir }, { timeoutMs: 5_000 });
        const fp2 = await adapter.validateTarget({ kind: "source_directory", path: dir }, { timeoutMs: 5_000 });
        expect(fp1).toBe(fp2);
        expect(fp1).toMatch(/^[a-f0-9]{16}$/);

        // Modifying code produces different fingerprint
        await fs.writeTextAtomic(join(dir, "src/handler.js"), fixedCodeWithGuard);
        const fp3 = await adapter.validateTarget({ kind: "source_directory", path: dir }, { timeoutMs: 5_000 });
        expect(fp3).not.toBe(fp1);
      });
    });

    it("rejects when target directory does not exist", async () => {
      const fs = new NodeFileSystemPort();
      const adapter = new JavascriptCfgMissingCheckAdapter({ filesystem: fs });
      await expect(adapter.validateTarget({
        kind: "source_directory",
        path: "/non/existent/path/for/sure",
      }, { timeoutMs: 5_000 })).rejects.toThrow(DomainError);
    });

    it("rejects when expected fingerprint mismatches", async () => {
      await withTempDirectory(async (dir) => {
        const fs = new NodeFileSystemPort();
        await fs.ensureDirectory(join(dir, "src"));
        await fs.writeTextAtomic(join(dir, "src/handler.js"), vulnerableCode);

        const adapter = new JavascriptCfgMissingCheckAdapter({ filesystem: fs });
        await expect(adapter.validateTarget({
          kind: "source_directory",
          path: dir,
          expected_fingerprint: "0000000000000000",
        }, { timeoutMs: 5_000 })).rejects.toThrow(DomainError);
      });
    });
  });

  describe("End-to-End Application Differential Research & Replay", () => {
    it("executes differential research across vulnerable and fixed source trees and achieves differential verification", async () => {
      await withTempDirectory(async (dir) => {
        const fs = new NodeFileSystemPort();
        const vulnDir = join(dir, "vulnerable");
        const fixedDir = join(dir, "fixed");

        await fs.ensureDirectory(join(vulnDir, "src"));
        await fs.ensureDirectory(join(fixedDir, "src"));

        await fs.writeTextAtomic(join(vulnDir, "src/handler.js"), vulnerableCode);
        await fs.writeTextAtomic(join(fixedDir, "src/handler.js"), fixedCodeWithGuard);

        const artifacts = new MemoryArtifactStore(join(dir, "runs"));
        const jsAdapter = new JavascriptCfgMissingCheckAdapter({ filesystem: fs });
        const missingCheck = new CompositeMissingCheckExecutionPort({
          javascript_cfg: jsAdapter,
        });

        const app = new Application({
          codeql: new FakeCodeqlPort(),
          artifacts,
          clock: new FixedClock(1_700_000_000_000),
          ids: new FixedIdGenerator(["run-js-diff-1"]),
          missingCheck,
        });

        const vulnFp = await jsAdapter.validateTarget({ kind: "source_directory", path: vulnDir }, { timeoutMs: 5_000 });
        const fixedFp = await jsAdapter.validateTarget({ kind: "source_directory", path: fixedDir }, { timeoutMs: 5_000 });

        const result = await app.research({
          action: "execute",
          capability: "missing_check",
          hypothesis_version: "autovul.missing-check/1",
          hypothesis,
          analyzer_id: "javascript_cfg",
          mode: "differential",
          target: {
            vulnerable: { kind: "source_directory", path: vulnDir, expected_fingerprint: vulnFp },
            fixed: { kind: "source_directory", path: fixedDir, expected_fingerprint: fixedFp },
          },
          budget: { timeout_ms: 5_000 },
          idempotency_key: "mcheck-js-diff-test",
        }) as MissingCheckExecutionResult;

        expect(result.capability).toBe("missing_check");
        expect(result.operation_status).toBe("completed");
        expect(result.verification_level).toBe("differential");
        expect(result.decision).toEqual({
          capability: "missing_check",
          outcome: "check_missing",
          fixed_outcome: "check_present",
          fixed_policy_satisfied: true,
        });

        // Test Replay reproduces identical result without model
        const replayed = await app.manageRun({
          action: "replay",
          run_id: result.run_id,
        }) as MissingCheckExecutionResult;

        expect(replayed.operation_status).toBe("completed");
        expect(replayed.verification_level).toBe("differential");
        expect(replayed.decision).toEqual({
          capability: "missing_check",
          outcome: "check_missing",
          fixed_outcome: "check_present",
          fixed_policy_satisfied: true,
        });

        // Tampering with vulnerable directory triggers replay fingerprint mismatch
        await fs.writeTextAtomic(join(vulnDir, "src/handler.js"), fixedCodeWithIfBranch);
        const tamperedReplay = await app.manageRun({
          action: "replay",
          run_id: result.run_id,
        }) as MissingCheckExecutionResult;

        expect(tamperedReplay.operation_status).toBe("blocked");
        expect(tamperedReplay.observations).toContainEqual(
          expect.objectContaining({ code: "MCHECK_REPLAY_FINGERPRINT_DIFFERENCE" }),
        );

        await app.close();
      });
    });
  });
});
