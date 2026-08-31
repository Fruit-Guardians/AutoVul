import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

const evidenceRoot = resolve(import.meta.dirname, "../specs/changes/admit-missing-check-capability-v1/evidence/openclaw-cve-2026-43572");

interface AdmissionEvidence {
  readonly status: string;
  readonly upstream: {
    readonly repository: string;
    readonly vulnerable_commit: string;
    readonly fixed_commit: string;
  };
  readonly hypothesis_candidate: {
    readonly operation_selector: { readonly kind: string; readonly name: string };
    readonly required_check_selector: { readonly kind: string; readonly name: string };
    readonly relation: string;
  };
  readonly observations: {
    readonly vulnerable: { readonly unchecked_witness_count: number; readonly operations: readonly string[] };
    readonly fixed: { readonly unchecked_witness_count: number };
  };
  readonly wrong_hypothesis_fixtures: Record<string, { readonly query: string; readonly sha256: string; readonly required_revision_action: string }>;
  readonly replay: { readonly query: string; readonly query_sha256: string; readonly requires_model_or_host_session: boolean };
}

async function readEvidence(): Promise<AdmissionEvidence> {
  return JSON.parse(await readFile(join(evidenceRoot, "RESULTS.json"), "utf8")) as AdmissionEvidence;
}

async function digest(relativePath: string): Promise<string> {
  return createHash("sha256").update(await readFile(join(evidenceRoot, relativePath))).digest("hex");
}

describe("MissingCheck admission evidence", () => {
  it("keeps one protected operation, one required check, and differential witnesses", async () => {
    const evidence = await readEvidence();

    expect(evidence.status).toBe("admission_evidence_only");
    expect(evidence.upstream.repository).toBe("https://github.com/openclaw/openclaw.git");
    expect(evidence.upstream.vulnerable_commit).toMatch(/^[0-9a-f]{40}$/);
    expect(evidence.upstream.fixed_commit).toMatch(/^[0-9a-f]{40}$/);
    expect(evidence.hypothesis_candidate.operation_selector).toEqual({ kind: "direct_call", name: "handleSigninTokenExchangeInvoke" });
    expect(evidence.hypothesis_candidate.required_check_selector).toEqual({ kind: "direct_call", name: "isSigninInvokeAuthorized" });
    expect(evidence.hypothesis_candidate.relation).toBe("same_callback_cfg_dominates_operation");
    expect(evidence.observations.vulnerable).toEqual({ unchecked_witness_count: 1, operations: ["handleSigninTokenExchangeInvoke"] });
    expect(evidence.observations.fixed.unchecked_witness_count).toBe(0);
  });

  it("binds replay and wrong-hypothesis records to their query digests", async () => {
    const evidence = await readEvidence();

    expect(evidence.replay.requires_model_or_host_session).toBe(false);
    await expect(digest(evidence.replay.query)).resolves.toBe(evidence.replay.query_sha256);
    await expect(digest(evidence.wrong_hypothesis_fixtures.wrong_operation.query)).resolves.toBe(evidence.wrong_hypothesis_fixtures.wrong_operation.sha256);
    await expect(digest(evidence.wrong_hypothesis_fixtures.wrong_check.query)).resolves.toBe(evidence.wrong_hypothesis_fixtures.wrong_check.sha256);
    expect(evidence.wrong_hypothesis_fixtures.wrong_operation.required_revision_action).toBe("revise_operation");
    expect(evidence.wrong_hypothesis_fixtures.wrong_check.required_revision_action).toBe("revise_check");
  });
});
