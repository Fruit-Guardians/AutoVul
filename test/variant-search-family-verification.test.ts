import { execFile as execFileCb } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import type {
  MissingCheckExecutionResult,
  MissingCheckHypothesis,
  VariantSearchExecutionResult,
  VariantSearchServiceRequest,
} from "@autovul/contracts";
import {
  Application,
  CompositeMissingCheckExecutionPort,
} from "@autovul/core";
import {
  GitVariantSearchAdapter,
  JavascriptCfgMissingCheckAdapter,
  NodeFileSystemPort,
} from "@autovul/codeql-runner";

import { FakeCodeqlPort, FixedClock, FixedIdGenerator, MemoryArtifactStore } from "./helpers.js";

const execFile = promisify(execFileCb);

async function runGit(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFile("git", args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" },
  });
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

describe("Variant Search v1 Family Verification & Owning-Capability Validation", () => {
  it("Family 1 (OpenClaw): discovers candidates, validates non-seed variant to differential, and proves high-similarity safe counter-example", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-fam1-"));
    try {
      const repoDir = join(root, "repo");
      await mkdir(repoDir, { recursive: true });

      const seedVuln = `
export function registerMSTeamsHandlers(app: any) {
  const result = handleSigninTokenExchangeInvoke(app);
  return result;
}
`;
      const variantVuln = `
export function registerActionHandlers(app: any) {
  const result = handleSigninTokenExchangeInvoke(app);
  return result;
}
`;
      const safeCode = `
export function registerSafeHandlers(app: any) {
  if (!isSigninInvokeAuthorized(app)) {
    return null;
  }
  const result = handleSigninTokenExchangeInvoke(app);
  return result;
}
`;
      const seedFixed = `
export function registerMSTeamsHandlers(app: any) {
  if (!isSigninInvokeAuthorized(app)) {
    return null;
  }
  const result = handleSigninTokenExchangeInvoke(app);
  return result;
}
`;
      const variantFixed = `
export function registerActionHandlers(app: any) {
  if (!isSigninInvokeAuthorized(app)) {
    return null;
  }
  const result = handleSigninTokenExchangeInvoke(app);
  return result;
}
`;

      const [vulnOid, fixedOid] = await createGitRepo(repoDir, [
        {
          message: "vulnerable: token exchange missing authorization",
          files: {
            "extensions/msteams/src/monitor-handler.ts": seedVuln,
            "extensions/msteams/src/action-handler.ts": variantVuln,
            "extensions/msteams/src/safe-handler.ts": safeCode,
            "extensions/msteams/src/unrelated.ts": "export function unrelated() { return 42; }",
          },
        },
        {
          message: "fixed: add authorization checks",
          files: {
            "extensions/msteams/src/monitor-handler.ts": seedFixed,
            "extensions/msteams/src/action-handler.ts": variantFixed,
          },
        },
      ]);

      const fs = new NodeFileSystemPort();
      const mcheckAdapter = new JavascriptCfgMissingCheckAdapter({
        trustedRoots: [repoDir],
        filesystem: fs,
      });
      const varSearchAdapter = new GitVariantSearchAdapter({
        trustedRoots: [repoDir],
      });

      const artifacts = new MemoryArtifactStore(join(root, "runs"));
      const clock = new FixedClock(1_700_000_000_000);
      const ids = new FixedIdGenerator([
        "run-seed-openclaw",
        "run-varsearch-openclaw",
        "run-variant-validate-openclaw",
        "run-safe-validate-openclaw",
      ]);

      const app = new Application({
        codeql: new FakeCodeqlPort(),
        artifacts,
        clock,
        ids,
        missingCheck: new CompositeMissingCheckExecutionPort({
          javascript_cfg: mcheckAdapter,
        }),
        variantSearch: varSearchAdapter,
      });

      // 1. Establish verified seed run with MissingCheck
      const seedHypothesis: MissingCheckHypothesis = {
        schema_version: "autovul.missing-check/1",
        hypothesis_id: "mcheck-openclaw-seed",
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

      const seedResult = (await app.research({
        action: "execute",
        capability: "missing_check",
        hypothesis_version: "autovul.missing-check/1",
        hypothesis: seedHypothesis,
        analyzer_id: "javascript_cfg",
        mode: "differential",
        target: {
          vulnerable: { kind: "git_revision", repository: repoDir, revision: vulnOid },
          fixed: { kind: "git_revision", repository: repoDir, revision: fixedOid },
        },
        budget: { timeout_ms: 30_000 },
        idempotency_key: "openclaw-seed-diff",
      })) as MissingCheckExecutionResult;

      expect(seedResult.operation_status).toBe("completed");
      expect(seedResult.decision.outcome).toBe("check_missing");
      expect(seedResult.decision.fixed_outcome).toBe("check_present");
      expect(seedResult.verification_level).toBe("differential");

      // 2. Execute Variant Search using the verified seed run
      const searchRequest: VariantSearchServiceRequest = {
        action: "execute",
        service: "variant_search",
        service_version: "autovul.variant-search/1",
        input: {
          seed_run_id: seedResult.run_id,
          corpus: [{ kind: "git_revision", repository: repoDir, revision: vulnOid }],
          strategy: "symbol_call_pattern",
          budget: { max_candidates: 10, max_files_per_target: 10, timeout_ms: 30_000 },
        },
      };

      const searchResult = (await app.research(searchRequest)) as VariantSearchExecutionResult;
      expect(searchResult.operation_status).toBe("completed");
      expect(searchResult.service).toBe("variant_search");
      expect(searchResult.observation.completeness).toBe("complete");
      expect(searchResult.observation.gaps).toEqual([]);
      expect(searchResult.observation.candidates).toHaveLength(4);

      const candidateFiles = [...new Set(searchResult.observation.candidates.map((c) => c.location.file))];
      expect(candidateFiles).toContain("extensions/msteams/src/monitor-handler.ts");
      expect(candidateFiles).toContain("extensions/msteams/src/action-handler.ts");
      expect(candidateFiles).toContain("extensions/msteams/src/safe-handler.ts");
      expect(candidateFiles).not.toContain("extensions/msteams/src/unrelated.ts");

      // Verify canonical candidate properties
      for (const candidate of searchResult.observation.candidates) {
        expect(candidate.candidate_id).toMatch(/^[a-f0-9]{64}$/);
        expect(candidate.evidence_digest).toMatch(/^[a-f0-9]{64}$/);
        expect(candidate.evidence_ref).toBe(`research/variant-search/candidates/${candidate.candidate_id}.json`);
      }

      // 3. Owning-Capability Validation: validate non-seed variant with MissingCheck
      const nonSeedCandidate = searchResult.observation.candidates.find(
        (c) => c.location.file === "extensions/msteams/src/action-handler.ts" && c.matched_symbols.includes("handleSigninTokenExchangeInvoke"),
      )!;
      expect(nonSeedCandidate).toBeDefined();

      const variantHypothesis: MissingCheckHypothesis = {
        schema_version: "autovul.missing-check/1",
        hypothesis_id: "mcheck-openclaw-variant-action",
        language: "javascript",
        operation: { kind: "direct_call", name: nonSeedCandidate.matched_symbols[0] },
        required_check: { kind: "direct_call", name: "isSigninInvokeAuthorized" },
        required_relation: "same_callback_cfg_dominates_operation",
        scope: {
          kind: "single_file_named_entry_cfg",
          file: nonSeedCandidate.location.file,
          entry: { kind: "named_function", name: nonSeedCandidate.location.enclosing_symbol! },
        },
      };

      const variantValidation = (await app.research({
        action: "execute",
        capability: "missing_check",
        hypothesis_version: "autovul.missing-check/1",
        hypothesis: variantHypothesis,
        analyzer_id: "javascript_cfg",
        mode: "differential",
        target: {
          vulnerable: { kind: "git_revision", repository: repoDir, revision: vulnOid },
          fixed: { kind: "git_revision", repository: repoDir, revision: fixedOid },
        },
        budget: { timeout_ms: 30_000 },
        idempotency_key: "openclaw-variant-diff",
      })) as MissingCheckExecutionResult;

      expect(variantValidation.operation_status).toBe("completed");
      expect(variantValidation.decision.outcome).toBe("check_missing");
      expect(variantValidation.decision.fixed_outcome).toBe("check_present");
      expect(variantValidation.verification_level).toBe("differential");

      // 4. Safe counter-example: MissingCheck demonstrates check_present on high-similarity safe candidate
      const safeCandidate = searchResult.observation.candidates.find(
        (c) => c.location.file === "extensions/msteams/src/safe-handler.ts" && c.matched_symbols.includes("handleSigninTokenExchangeInvoke"),
      )!;
      expect(safeCandidate).toBeDefined();

      const safeHypothesis: MissingCheckHypothesis = {
        schema_version: "autovul.missing-check/1",
        hypothesis_id: "mcheck-openclaw-safe-counter",
        language: "javascript",
        operation: { kind: "direct_call", name: safeCandidate.matched_symbols[0] },
        required_check: { kind: "direct_call", name: "isSigninInvokeAuthorized" },
        required_relation: "same_callback_cfg_dominates_operation",
        scope: {
          kind: "single_file_named_entry_cfg",
          file: safeCandidate.location.file,
          entry: { kind: "named_function", name: safeCandidate.location.enclosing_symbol! },
        },
      };

      const safeValidation = (await app.research({
        action: "execute",
        capability: "missing_check",
        hypothesis_version: "autovul.missing-check/1",
        hypothesis: safeHypothesis,
        analyzer_id: "javascript_cfg",
        mode: "reproduce",
        target: {
          vulnerable: { kind: "git_revision", repository: repoDir, revision: vulnOid },
        },
        budget: { timeout_ms: 30_000 },
        idempotency_key: "openclaw-safe-reproduce",
      })) as MissingCheckExecutionResult;

      expect(safeValidation.operation_status).toBe("completed");
      expect(safeValidation.decision.outcome).toBe("check_present");
      expect(safeValidation.verification_level).toBe("compiled");

      // 5. Replay of Variant Search run
      const replay = await app.manageRun({
        action: "replay",
        run_id: searchResult.run_id,
      });

      expect(replay).toMatchObject({
        service: "variant_search",
        service_version: "autovul.variant-search/1",
        status: "identical",
        divergence_reasons: [],
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("Family 2 (Webhook Verification): discovers candidates, validates non-seed variant, and proves safe counter-example", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-fam2-"));
    try {
      const repoDir = join(root, "repo");
      await mkdir(repoDir, { recursive: true });

      const seedVuln = `
export function handlePaymentWebhook(req: any) {
  handleWebhookDispatch(req);
}
`;
      const variantVuln = `
export function handleInvoiceWebhook(req: any) {
  handleWebhookDispatch(req);
}
`;
      const safeCode = `
export function handleAuditWebhook(req: any) {
  if (!verifyWebhookSignature(req)) {
    return;
  }
  handleWebhookDispatch(req);
}
`;
      const seedFixed = `
export function handlePaymentWebhook(req: any) {
  if (!verifyWebhookSignature(req)) {
    return;
  }
  handleWebhookDispatch(req);
}
`;
      const variantFixed = `
export function handleInvoiceWebhook(req: any) {
  if (!verifyWebhookSignature(req)) {
    return;
  }
  handleWebhookDispatch(req);
}
`;

      const [vulnOid, fixedOid] = await createGitRepo(repoDir, [
        {
          message: "vulnerable: missing webhook signature check",
          files: {
            "src/webhooks/payment.ts": seedVuln,
            "src/webhooks/invoice.ts": variantVuln,
            "src/webhooks/audit.ts": safeCode,
          },
        },
        {
          message: "fixed: add signature verification",
          files: {
            "src/webhooks/payment.ts": seedFixed,
            "src/webhooks/invoice.ts": variantFixed,
          },
        },
      ]);

      const fs = new NodeFileSystemPort();
      const mcheckAdapter = new JavascriptCfgMissingCheckAdapter({
        trustedRoots: [repoDir],
        filesystem: fs,
      });
      const varSearchAdapter = new GitVariantSearchAdapter({
        trustedRoots: [repoDir],
      });

      const artifacts = new MemoryArtifactStore(join(root, "runs"));
      const clock = new FixedClock(1_700_000_000_000);
      const ids = new FixedIdGenerator([
        "run-seed-webhook",
        "run-varsearch-webhook",
        "run-variant-validate-webhook",
        "run-safe-validate-webhook",
      ]);

      const app = new Application({
        codeql: new FakeCodeqlPort(),
        artifacts,
        clock,
        ids,
        missingCheck: new CompositeMissingCheckExecutionPort({
          javascript_cfg: mcheckAdapter,
        }),
        variantSearch: varSearchAdapter,
      });

      // 1. Seed run
      const seedResult = (await app.research({
        action: "execute",
        capability: "missing_check",
        hypothesis_version: "autovul.missing-check/1",
        hypothesis: {
          schema_version: "autovul.missing-check/1",
          hypothesis_id: "mcheck-webhook-seed",
          language: "javascript",
          operation: { kind: "direct_call", name: "handleWebhookDispatch" },
          required_check: { kind: "direct_call", name: "verifyWebhookSignature" },
          required_relation: "same_callback_cfg_dominates_operation",
          scope: {
            kind: "single_file_named_entry_cfg",
            file: "src/webhooks/payment.ts",
            entry: { kind: "named_function", name: "handlePaymentWebhook" },
          },
        },
        analyzer_id: "javascript_cfg",
        mode: "differential",
        target: {
          vulnerable: { kind: "git_revision", repository: repoDir, revision: vulnOid },
          fixed: { kind: "git_revision", repository: repoDir, revision: fixedOid },
        },
        budget: { timeout_ms: 30_000 },
        idempotency_key: "webhook-seed-diff",
      })) as MissingCheckExecutionResult;

      expect(seedResult.decision.outcome).toBe("check_missing");
      expect(seedResult.decision.fixed_outcome).toBe("check_present");
      expect(seedResult.verification_level).toBe("differential");

      // 2. Variant Search
      const searchResult = (await app.research({
        action: "execute",
        service: "variant_search",
        service_version: "autovul.variant-search/1",
        input: {
          seed_run_id: seedResult.run_id,
          corpus: [{ kind: "git_revision", repository: repoDir, revision: vulnOid }],
          strategy: "symbol_call_pattern",
          budget: { max_candidates: 10, max_files_per_target: 10, timeout_ms: 30_000 },
        },
      })) as VariantSearchExecutionResult;

      expect(searchResult.observation.candidates).toHaveLength(4);
      expect(searchResult.observation.completeness).toBe("complete");

      // 3. Owning Capability non-seed variant validation
      const invoiceCandidate = searchResult.observation.candidates.find(
        (c) => c.location.file === "src/webhooks/invoice.ts" && c.matched_symbols.includes("handleWebhookDispatch"),
      )!;
      expect(invoiceCandidate).toBeDefined();

      const invoiceValidation = (await app.research({
        action: "execute",
        capability: "missing_check",
        hypothesis_version: "autovul.missing-check/1",
        hypothesis: {
          schema_version: "autovul.missing-check/1",
          hypothesis_id: "mcheck-webhook-invoice",
          language: "javascript",
          operation: { kind: "direct_call", name: "handleWebhookDispatch" },
          required_check: { kind: "direct_call", name: "verifyWebhookSignature" },
          required_relation: "same_callback_cfg_dominates_operation",
          scope: {
            kind: "single_file_named_entry_cfg",
            file: invoiceCandidate.location.file,
            entry: { kind: "named_function", name: invoiceCandidate.location.enclosing_symbol! },
          },
        },
        analyzer_id: "javascript_cfg",
        mode: "differential",
        target: {
          vulnerable: { kind: "git_revision", repository: repoDir, revision: vulnOid },
          fixed: { kind: "git_revision", repository: repoDir, revision: fixedOid },
        },
        budget: { timeout_ms: 30_000 },
        idempotency_key: "webhook-invoice-diff",
      })) as MissingCheckExecutionResult;

      expect(invoiceValidation.decision.outcome).toBe("check_missing");
      expect(invoiceValidation.decision.fixed_outcome).toBe("check_present");
      expect(invoiceValidation.verification_level).toBe("differential");

      // 4. Safe counter-example check
      const auditCandidate = searchResult.observation.candidates.find(
        (c) => c.location.file === "src/webhooks/audit.ts" && c.matched_symbols.includes("handleWebhookDispatch"),
      )!;
      expect(auditCandidate).toBeDefined();

      const auditValidation = (await app.research({
        action: "execute",
        capability: "missing_check",
        hypothesis_version: "autovul.missing-check/1",
        hypothesis: {
          schema_version: "autovul.missing-check/1",
          hypothesis_id: "mcheck-webhook-audit",
          language: "javascript",
          operation: { kind: "direct_call", name: "handleWebhookDispatch" },
          required_check: { kind: "direct_call", name: "verifyWebhookSignature" },
          required_relation: "same_callback_cfg_dominates_operation",
          scope: {
            kind: "single_file_named_entry_cfg",
            file: auditCandidate.location.file,
            entry: { kind: "named_function", name: auditCandidate.location.enclosing_symbol! },
          },
        },
        analyzer_id: "javascript_cfg",
        mode: "reproduce",
        target: {
          vulnerable: { kind: "git_revision", repository: repoDir, revision: vulnOid },
        },
        budget: { timeout_ms: 30_000 },
        idempotency_key: "webhook-audit-reproduce",
      })) as MissingCheckExecutionResult;

      expect(auditValidation.decision.outcome).toBe("check_present");
      expect(auditValidation.verification_level).toBe("compiled");

      // 5. Replay
      const replay = await app.manageRun({
        action: "replay",
        run_id: searchResult.run_id,
      });

      expect(replay).toMatchObject({
        service: "variant_search",
        service_version: "autovul.variant-search/1",
        status: "identical",
        divergence_reasons: [],
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
