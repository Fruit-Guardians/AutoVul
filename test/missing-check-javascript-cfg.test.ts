import { describe, expect, it } from "vitest";
import { execFile as execFileCb } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

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
  LocalArtifactStore,
  NodeFileSystemPort,
} from "@autovul/codeql-runner";
import {
  FakeCodeqlPort,
  FixedClock,
  FixedIdGenerator,
  MemoryArtifactStore,
} from "./helpers.js";

const execFile = promisify(execFileCb);

const hypothesis: MissingCheckHypothesis = {
  schema_version: "autovul.missing-check/1",
  hypothesis_id: "mcheck-openclaw-43572",
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
  const dir = await mkdtemp(join(tmpdir(), "autovul-mcheck-js-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe("JavascriptCfgMissingCheckAdapter (Sound CFG & GitRevision Target)", () => {
  describe("OpenClaw CVE-2026-43572 Real Case", () => {
    it("executes differential research and replay with evidence immutability", async () => {
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });

        const [vulnOid, fixedOid] = await createGitRepo(repoDir, [
          {
            message: "vulnerable: missing sender authorization",
            files: { "extensions/msteams/src/monitor-handler.ts": openclawVulnCode },
          },
          {
            message: "fixed: add sender authorization guard",
            files: { "extensions/msteams/src/monitor-handler.ts": openclawFixedCode },
          },
        ]);

        const fs = new NodeFileSystemPort();
        const adapter = new JavascriptCfgMissingCheckAdapter({
          trustedRoots: [repoDir],
          filesystem: fs,
        });

        const app = new Application({
          codeql: new FakeCodeqlPort(),
          artifacts: new MemoryArtifactStore(join(dir, "runs")),
          clock: new FixedClock(1_700_000_000_000),
          ids: new FixedIdGenerator(["run-openclaw-diff-1"]),
          missingCheck: new CompositeMissingCheckExecutionPort({
            javascript_cfg: adapter,
          }),
        });

        const result = await app.research({
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
          budget: { timeout_ms: 10_000 },
          idempotency_key: "openclaw-cve-2026-43572",
        });

        expect(result.valid).toBeUndefined();
        const execResult = result as MissingCheckExecutionResult;
        expect(execResult.verification_level).toBe("differential");
        expect(execResult.decision.outcome).toBe("check_missing");
        expect(execResult.decision.fixed_outcome).toBe("check_present");
        expect(execResult.decision.fixed_policy_satisfied).toBe(true);

        // Replay: must reproduce exact differential verdict and preserve primary evidence
        const replay = await app.manageRun({ action: "replay", run_id: execResult.run_id });
        const replayResult = replay as MissingCheckExecutionResult;
        expect(replayResult.verification_level).toBe("differential");
        expect(replayResult.decision.outcome).toBe("check_missing");
        expect(replayResult.decision.fixed_outcome).toBe("check_present");
      });
    });
  });

  describe("Adversarial Guard Polarity Counter-Example Matrix", () => {
    it("flags inverted guard polarity as UNCHECKED (vulnerable)", async () => {
      // if (check()) return; op(); -> Exits when authorized; fallthrough is unauthorized!
      const invertedGuardCode = `
export function registerMSTeamsHandlers(app) {
  if (isSigninInvokeAuthorized(app)) {
    return null;
  }
  return handleSigninTokenExchangeInvoke(app);
}
`;
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "inverted guard", files: { "extensions/msteams/src/monitor-handler.ts": invertedGuardCode } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        const obs = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-pol-1",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 5_000 });

        expect(obs.relation.state).toBe("unchecked_witness");
        expect(obs.relation.unchecked_witnesses.length).toBe(1);
      });
    });

    it("flags operation inside negated check branch as UNCHECKED (vulnerable)", async () => {
      // if (!check()) { op(); } -> Operation called when check is FALSE!
      const negatedBranchCode = `
export function registerMSTeamsHandlers(app) {
  if (!isSigninInvokeAuthorized(app)) {
    return handleSigninTokenExchangeInvoke(app);
  }
  return null;
}
`;
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "negated branch", files: { "extensions/msteams/src/monitor-handler.ts": negatedBranchCode } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        const obs = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-pol-2",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 5_000 });

        expect(obs.relation.state).toBe("unchecked_witness");
        expect(obs.relation.unchecked_witnesses.length).toBe(1);
      });
    });

    it("recognizes operation inside positive check branch as CHECKED (safe)", async () => {
      // if (check()) { op(); } -> Operation called when check is TRUE!
      const positiveBranchCode = `
export function registerMSTeamsHandlers(app) {
  if (isSigninInvokeAuthorized(app)) {
    return handleSigninTokenExchangeInvoke(app);
  }
  return null;
}
`;
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "positive branch", files: { "extensions/msteams/src/monitor-handler.ts": positiveBranchCode } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        const obs = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-pol-3",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 5_000 });

        expect(obs.relation.state).toBe("checked_witness");
        expect(obs.relation.checked_witnesses.length).toBe(1);
      });
    });

    it("flags bypass paths as UNCHECKED (vulnerable)", async () => {
      const bypassCode = `
export function registerMSTeamsHandlers(app) {
  if (app.bypassAuth) {
    return handleSigninTokenExchangeInvoke(app);
  } else {
    if (!isSigninInvokeAuthorized(app)) {
      return null;
    }
    return handleSigninTokenExchangeInvoke(app);
  }
}
`;
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "bypass path", files: { "extensions/msteams/src/monitor-handler.ts": bypassCode } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        const obs = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-pol-4",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 5_000 });

        expect(obs.relation.state).toBe("unchecked_witness");
        expect(obs.relation.unchecked_witnesses.length).toBe(1);
      });
    });
  });

  describe("Incomplete Classification on Unsupported Constructs", () => {
    it("reports incomplete when entry function contains a loop", async () => {
      const loopCode = `
export function registerMSTeamsHandlers(app) {
  for (let i = 0; i < 10; i++) {
    handleSigninTokenExchangeInvoke(app);
  }
}
`;
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "loop code", files: { "extensions/msteams/src/monitor-handler.ts": loopCode } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        const obs = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-loop",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 5_000 });

        expect(obs.completeness.vulnerable.status).toBe("incomplete");
        expect(obs.relation.state).toBe("inconclusive");
        expect(obs.capability_gaps).toEqual(expect.arrayContaining([
          expect.objectContaining({ code: "MCHECK_UNSUPPORTED_LOOP_CONSTRUCT" }),
        ]));
      });
    });

    it("reports incomplete when entry function is not found", async () => {
      const wrongFnCode = `
export function otherFunction(app) {
  handleSigninTokenExchangeInvoke(app);
}
`;
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "wrong fn", files: { "extensions/msteams/src/monitor-handler.ts": wrongFnCode } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        const obs = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-no-entry",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 5_000 });

        expect(obs.completeness.vulnerable.status).toBe("incomplete");
        expect(obs.relation.state).toBe("inconclusive");
        expect(obs.capability_gaps).toEqual(expect.arrayContaining([
          expect.objectContaining({ code: "MCHECK_ENTRY_NOT_FOUND" }),
        ]));
      });
    });

    it("reports incomplete when file does not exist in the commit", async () => {
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "other file", files: { "unrelated.txt": "hello" } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        const obs = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-no-file",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 5_000 });

        expect(obs.completeness.vulnerable.status).toBe("incomplete");
        expect(obs.relation.state).toBe("inconclusive");
        expect(obs.capability_gaps).toEqual(expect.arrayContaining([
          expect.objectContaining({ code: "MCHECK_FILE_NOT_FOUND" }),
        ]));
      });
    });

    it("reports incomplete when entry function contains a with statement", async () => {
      const withCode = `
export function registerMSTeamsHandlers(app) {
  with (app) {
    handleSigninTokenExchangeInvoke(app);
  }
}
`;
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "with code", files: { "extensions/msteams/src/monitor-handler.ts": withCode } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        const obs = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-with",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 5_000 });

        expect(obs.completeness.vulnerable.status).toBe("incomplete");
        expect(obs.relation.state).toBe("inconclusive");
        expect(obs.capability_gaps).toEqual(expect.arrayContaining([
          expect.objectContaining({ code: "MCHECK_UNSUPPORTED_WITH_CONSTRUCT" }),
        ]));
      });
    });

    it("reports incomplete when ternary conditional expression contains op or check", async () => {
      const ternaryCode = `
export function registerMSTeamsHandlers(app) {
  return isSigninInvokeAuthorized(app) ? handleSigninTokenExchangeInvoke(app) : null;
}
`;
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "ternary code", files: { "extensions/msteams/src/monitor-handler.ts": ternaryCode } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        const obs = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-ternary",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 5_000 });

        expect(obs.completeness.vulnerable.status).toBe("incomplete");
        expect(obs.relation.state).toBe("inconclusive");
        expect(obs.capability_gaps).toEqual(expect.arrayContaining([
          expect.objectContaining({ code: "MCHECK_UNSUPPORTED_SHORT_CIRCUIT_CONSTRUCT" }),
        ]));
      });
    });

    it("reports incomplete when short-circuit binary expression contains op or check", async () => {
      const shortCircuitCode = `
export function registerMSTeamsHandlers(app) {
  isSigninInvokeAuthorized(app) && handleSigninTokenExchangeInvoke(app);
}
`;
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "short circuit", files: { "extensions/msteams/src/monitor-handler.ts": shortCircuitCode } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        const obs = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-short-circuit",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 5_000 });

        expect(obs.completeness.vulnerable.status).toBe("incomplete");
        expect(obs.relation.state).toBe("inconclusive");
        expect(obs.capability_gaps).toEqual(expect.arrayContaining([
          expect.objectContaining({ code: "MCHECK_UNSUPPORTED_SHORT_CIRCUIT_CONSTRUCT" }),
        ]));
      });
    });

    it("reports incomplete when statement depth exceeds MAX_STATEMENT_DEPTH (250)", async () => {
      const statements = Array.from({ length: 255 }, (_, i) => `  const dummy${i} = ${i};`).join("\n");
      const deepCode = `
export function registerMSTeamsHandlers(app) {
${statements}
  return handleSigninTokenExchangeInvoke(app);
}
`;
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "deep statements", files: { "extensions/msteams/src/monitor-handler.ts": deepCode } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        const obs = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-deep",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 5_000 });

        expect(obs.completeness.vulnerable.status).toBe("incomplete");
        expect(obs.relation.state).toBe("inconclusive");
        expect(obs.capability_gaps).toEqual(expect.arrayContaining([
          expect.objectContaining({ code: "MCHECK_STATEMENT_DEPTH_EXCEEDED" }),
        ]));
      });
    });

    it("reports incomplete when path breadth exceeds MAX_PATH_BREADTH (64)", async () => {
      const branches = Array.from({ length: 7 }, (_, i) => `  if (app.flag${i}) { const a${i} = 1; } else { const b${i} = 2; }`).join("\n");
      const wideCode = `
export function registerMSTeamsHandlers(app) {
${branches}
  return handleSigninTokenExchangeInvoke(app);
}
`;
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "wide branching", files: { "extensions/msteams/src/monitor-handler.ts": wideCode } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        const obs = await adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-wide",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 5_000 });

        expect(obs.completeness.vulnerable.status).toBe("incomplete");
        expect(obs.relation.state).toBe("inconclusive");
        expect(obs.capability_gaps).toEqual(expect.arrayContaining([
          expect.objectContaining({ code: "MCHECK_PATH_BREADTH_EXCEEDED" }),
        ]));
      });
    });
  });

  describe("Security Boundaries & Fingerprints", () => {
    it("rejects repository outside trusted roots", async () => {
      await withTempDir(async (dir) => {
        const untrustedRepo = join(dir, "untrusted");
        const trustedRoot = join(dir, "trusted");
        await mkdir(untrustedRepo, { recursive: true });
        await mkdir(trustedRoot, { recursive: true });

        const [oid] = await createGitRepo(untrustedRepo, [
          { message: "init", files: { "README.md": "hi" } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [trustedRoot] });
        await expect(adapter.validateTarget({
          kind: "git_revision",
          repository: untrustedRepo,
          revision: oid,
        }, { timeoutMs: 5_000 })).rejects.toMatchObject<Partial<DomainError>>({
          code: "CHANGE_OBSERVATION_REPOSITORY_UNTRUSTED",
        });
      });
    });

    it("rejects when expected fingerprint does not match revision OID", async () => {
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "init", files: { "README.md": "hi" } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        await expect(adapter.validateTarget({
          kind: "git_revision",
          repository: repoDir,
          revision: oid,
          expected_fingerprint: "0123456789abcdef0123456789abcdef01234567",
        }, { timeoutMs: 5_000 })).rejects.toMatchObject<Partial<DomainError>>({
          code: "DATABASE_FINGERPRINT_MISMATCH",
        });
      });
    });
  });

  describe("Replay Immutability & Deadline Enforcement", () => {
    it("detects evidence mutation during replay and marks verification_level generated", async () => {
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });

        const [vulnOid, fixedOid] = await createGitRepo(repoDir, [
          {
            message: "vulnerable",
            files: { "extensions/msteams/src/monitor-handler.ts": openclawVulnCode },
          },
          {
            message: "fixed",
            files: { "extensions/msteams/src/monitor-handler.ts": openclawFixedCode },
          },
        ]);

        const fs = new NodeFileSystemPort();
        const baseAdapter = new JavascriptCfgMissingCheckAdapter({
          trustedRoots: [repoDir],
          filesystem: fs,
        });

        let tamperOnReplay = false;
        const mutatingAdapter = {
          execute: async (req: Parameters<JavascriptCfgMissingCheckAdapter["execute"]>[0], opts: Parameters<JavascriptCfgMissingCheckAdapter["execute"]>[1]) => {
            const obs = await baseAdapter.execute(req, opts);
            if (tamperOnReplay && req.workspace === "replay") {
              const originalEvidence = join(req.artifactRoot, "missing-check", req.hypothesis.hypothesis_id, "vulnerable", "witnesses.json");
              await fs.writeTextAtomic(originalEvidence, JSON.stringify({ tampered: true }));
            }
            return obs;
          },
          validateTarget: (target: Parameters<JavascriptCfgMissingCheckAdapter["validateTarget"]>[0], opts: Parameters<JavascriptCfgMissingCheckAdapter["validateTarget"]>[1]) =>
            baseAdapter.validateTarget(target, opts),
        };

        const app = new Application({
          codeql: new FakeCodeqlPort(),
          artifacts: new LocalArtifactStore(join(dir, "runs"), fs),
          clock: new FixedClock(1_700_000_000_000),
          ids: new FixedIdGenerator(["run-tamper-1"]),
          missingCheck: new CompositeMissingCheckExecutionPort({
            javascript_cfg: mutatingAdapter as unknown as JavascriptCfgMissingCheckAdapter,
          }),
        });

        const result = await app.research({
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
          budget: { timeout_ms: 10_000 },
          idempotency_key: "openclaw-tamper-test",
        });

        expect((result as MissingCheckExecutionResult).verification_level).toBe("differential");

        tamperOnReplay = true;
        const replay = await app.manageRun({ action: "replay", run_id: (result as MissingCheckExecutionResult).run_id });
        const replayResult = replay as MissingCheckExecutionResult;
        expect(replayResult.verification_level).toBe("generated");
        expect(replayResult.observations).toEqual(expect.arrayContaining([
          expect.objectContaining({ code: "MCHECK_REPLAY_EVIDENCE_MUTATED" }),
        ]));
      });
    });

    it("fails replay with MCHECK_REPLAY_FINGERPRINT_DIFFERENCE when recorded fingerprint diverges", async () => {
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });

        const [vulnOid, fixedOid] = await createGitRepo(repoDir, [
          {
            message: "vulnerable",
            files: { "extensions/msteams/src/monitor-handler.ts": openclawVulnCode },
          },
          {
            message: "fixed",
            files: { "extensions/msteams/src/monitor-handler.ts": openclawFixedCode },
          },
        ]);

        const fs = new NodeFileSystemPort();
        const adapter = new JavascriptCfgMissingCheckAdapter({
          trustedRoots: [repoDir],
          filesystem: fs,
        });

        const app = new Application({
          codeql: new FakeCodeqlPort(),
          artifacts: new LocalArtifactStore(join(dir, "runs"), fs),
          clock: new FixedClock(1_700_000_000_000),
          ids: new FixedIdGenerator(["run-fp-1"]),
          missingCheck: new CompositeMissingCheckExecutionPort({
            javascript_cfg: adapter,
          }),
        });

        const result = await app.research({
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
          budget: { timeout_ms: 10_000 },
          idempotency_key: "openclaw-fp-test",
        });

        expect((result as MissingCheckExecutionResult).verification_level).toBe("differential");

        const runId = (result as MissingCheckExecutionResult).run_id;
        const resultArtifactPath = join(dir, "runs", runId, "research", "missing-check", "result.json");
        const artifactJson = JSON.parse(await fs.readText(resultArtifactPath));
        artifactJson.target_fingerprints.vulnerable = "0123456789abcdef0123456789abcdef01234567";
        await fs.writeTextAtomic(resultArtifactPath, JSON.stringify(artifactJson));

        const replay = await app.manageRun({ action: "replay", run_id: runId });
        const replayResult = replay as MissingCheckExecutionResult;
        expect(replayResult.operation_status).toBe("blocked");
        expect(replayResult.observations).toEqual(expect.arrayContaining([
          expect.objectContaining({ code: "MCHECK_REPLAY_FINGERPRINT_DIFFERENCE" }),
        ]));
      });
    });

    it("enforces execution deadline and raises PROCESS_TIMEOUT when timeoutMs is 0", async () => {
      await withTempDir(async (dir) => {
        const repoDir = join(dir, "repo");
        await mkdir(repoDir, { recursive: true });
        const [oid] = await createGitRepo(repoDir, [
          { message: "init", files: { "extensions/msteams/src/monitor-handler.ts": openclawVulnCode } },
        ]);

        const adapter = new JavascriptCfgMissingCheckAdapter({ trustedRoots: [repoDir] });
        await expect(adapter.execute({
          hypothesis,
          target: { vulnerable: { kind: "git_revision", repository: repoDir, revision: oid } },
          analyzer_id: "javascript_cfg",
          mode: "reproduce",
          runId: "run-timeout-1",
          artifactRoot: join(dir, "artifacts"),
        }, { timeoutMs: 0 })).rejects.toMatchObject<Partial<DomainError>>({
          code: "PROCESS_TIMEOUT",
        });
      });
    });
  });
});
