import {
  CONTRACTS_VERSION,
  DomainError,
  parseSchema,
  QueryPackManifestSchema,
  RunIdSchema,
  stableDigest,
  type QueryPackManifest,
} from "@pure-auto-codeql/contracts";

import type { CodeqlOperationOptions } from "../ports.js";
import { qlpackForLanguage } from "../language-packs.js";
import type { CodeqlWorkflowContext } from "./context.js";

export async function finalizeWorkflow(
  context: CodeqlWorkflowContext,
  input: unknown,
  options: CodeqlOperationOptions,
): Promise<QueryPackManifest> {
  const runId = parseSchema(RunIdSchema, input, "run id");
  return context.repository.withRunOperation(runId, options, async () => {
    const state = await context.repository.load(runId);
    const verification = [...state.verifications].reverse().find((item) => item.status === "passed");
    if (verification === undefined) {
      throw new DomainError("INVALID_STATE_TRANSITION", "state", "A passed query verification is required before finalization", false, { runId });
    }
    const candidate = state.candidates.find((item) => item.candidate_id === verification.candidate_id);
    if (candidate === undefined) {
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Verification references a missing query candidate", false, { runId, candidateId: verification.candidate_id });
    }

    const packRoot = "query-pack";
    const queryText = candidate.ql_text;
    const specText = `${JSON.stringify(state.spec, null, 2)}\n`;
    const verificationText = `${JSON.stringify(verification, null, 2)}\n`;
    const candidateText = `${JSON.stringify(candidate, null, 2)}\n`;
    const intentText = candidate.intent === undefined ? undefined : `${JSON.stringify(candidate.intent, null, 2)}\n`;
    const evidenceText = `${JSON.stringify({
      schema_version: CONTRACTS_VERSION,
      run_id: runId,
      candidate_id: candidate.candidate_id,
      vulnerable: verification.vulnerable,
      fixed: verification.fixed,
      diagnostics: verification.diagnostics,
    }, null, 2)}\n`;
    const pack = parseSchema(QueryPackManifestSchema, {
      schema_version: CONTRACTS_VERSION,
      pack_id: `pack-${runId}-${candidate.query_id}`,
      run_id: runId,
      spec_id: state.spec.spec_id,
      query_id: candidate.query_id,
      language: state.spec.language,
      cwe: state.spec.cwe,
      provenance: state.spec.provenance.source,
      files: {
        query: "query.ql",
        candidate: "candidate.json",
        spec: "spec.json",
        verification: "verification.json",
        qlpack: "qlpack.yml",
        evidence: "evidence.json",
        reproduce: "REPRODUCE.md",
        manifest: "query-pack-manifest.json",
        ...(candidate.intent === undefined ? {} : { exact: "exact.ql", intent: "intent.json" }),
        ...(candidate.probe_evidence === undefined ? {} : { probe_evidence: "probe-evidence.json" }),
      },
      replay: {
        working_directory: ".",
        compile: ["codeql", "query", "compile", "query.ql", "--threads=1"],
        vulnerable: ["codeql", "database", "analyze", "<vulnerable_database>", "query.ql", "--rerun", "--format=sarif-latest", "--output=vulnerable.sarif", "--threads=1"],
        ...(state.spec.fixed_database === undefined ? {} : { fixed: ["codeql", "database", "analyze", "<fixed_database>", "query.ql", "--rerun", "--format=sarif-latest", "--output=fixed.sarif", "--threads=1"] }),
        databases: {
          vulnerable: state.spec.vulnerable_database.path,
          ...(state.spec.fixed_database === undefined ? {} : { fixed: state.spec.fixed_database.path }),
        },
      },
      verification,
      integrity: {
        query: stableDigest(queryText),
        candidate: stableDigest(candidateText),
        spec: stableDigest(specText),
        verification: stableDigest(verificationText),
      },
      created_at: context.clock.now(),
      platform: "posix",
    }, "query pack manifest");

    await context.repository.writeArtifact(runId, `${packRoot}/query.ql`, queryText);
    await context.repository.writeArtifact(runId, `${packRoot}/candidate.json`, candidateText);
    await context.repository.writeArtifact(runId, `${packRoot}/spec.json`, specText);
    await context.repository.writeArtifact(runId, `${packRoot}/verification.json`, verificationText);
    await context.repository.writeArtifact(runId, `${packRoot}/qlpack.yml`, candidate.qlpack_yml ?? qlpackForLanguage(state.spec.language));
    await context.repository.writeArtifact(runId, `${packRoot}/evidence.json`, evidenceText);
    if (intentText !== undefined) {
      await context.repository.writeArtifact(runId, `${packRoot}/exact.ql`, queryText);
      await context.repository.writeArtifact(runId, `${packRoot}/intent.json`, intentText);
    }
    if (candidate.probe_evidence !== undefined) {
      await context.repository.writeArtifact(runId, `${packRoot}/probe-evidence.json`, `${JSON.stringify(candidate.probe_evidence, null, 2)}\n`);
    }
    await context.repository.writeArtifact(runId, `${packRoot}/REPRODUCE.md`, reproduceText(state.spec.vulnerable_database.path, state.spec.fixed_database?.path));
    await context.repository.writeArtifact(runId, `${packRoot}/query-pack-manifest.json`, `${JSON.stringify(pack, null, 2)}\n`);
    await context.repository.save(runId, { ...state, pack });
    await context.status.complete(runId, verification.verification_level, "workflow_finalize");
    const completedRun = await context.status.get(runId);
    await context.cases.update({ ...state, pack }, completedRun, "completed", pack.pack_id);
    return pack;
  });
}

function reproduceText(vulnerableDatabase: string, fixedDatabase: string | undefined): string {
  return `# Reproduce\n\nRun from the Query Pack directory:\n\n\`codeql query compile query.ql --threads=1\`\n\n\`codeql database analyze <vulnerable_database> query.ql --rerun --format=sarif-latest --output=vulnerable.sarif --threads=1\`\n${fixedDatabase === undefined ? "" : "\n\`codeql database analyze <fixed_database> query.ql --rerun --format=sarif-latest --output=fixed.sarif --threads=1\`\n"}\nThe original vulnerable database path was: ${vulnerableDatabase}\n${fixedDatabase === undefined ? "No fixed database was provided.\n" : `The original fixed database path was: ${fixedDatabase}\n`}For relocated replay use: pure-auto-codeql query-pack verify <pack-dir> --vulnerable-db <path> [--fixed-db <path>]\nWhen the Query Pack and databases share a non-root directory, the CLI infers that directory as the trusted workspace. Use --workspace-root <path> when they are in separate locations.\n`;
}
