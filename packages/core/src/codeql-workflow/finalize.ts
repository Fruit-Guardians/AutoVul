import {
  CONTRACTS_VERSION,
  DomainError,
  parseSchema,
  QueryPackManifestSchema,
  RunIdSchema,
  stableDigest,
  type QueryPackManifest,
} from "@pure-auto-codeql/contracts";

import type { ArtifactBundleFile, CodeqlOperationOptions, StagedArtifactBundle } from "../ports.js";
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
    if (state.pack !== undefined) {
      await context.repository.reconcile(runId);
      return state.pack;
    }
    const verification = [...state.verifications].reverse().find((item) => item.status === "passed");
    if (verification === undefined) throw new DomainError("INVALID_STATE_TRANSITION", "state", "A passed query verification is required before finalization", false, { runId });
    const candidate = state.candidates.find((item) => item.candidate_id === verification.candidate_id);
    if (candidate === undefined) throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Verification references a missing query candidate", false, { runId, candidateId: verification.candidate_id });

    const packId = `pack-${runId}-${candidate.query_id}`;
    const existingPack = await readExistingPack(context, runId, packId);
    const pack = existingPack ?? buildPack(context, runId, state, candidate, verification, packId);
    const files = packFiles(state, candidate, verification, pack);
    const operationId = `finalize-${stableDigest(`${runId}:${candidate.candidate_id}:${pack.pack_id}`)}`;
    let bundle: StagedArtifactBundle | undefined;
    let promoted = existingPack !== undefined;
    try {
      if (existingPack === undefined) {
        if (options.signal?.aborted) throw cancelledBeforeCommit(runId, operationId);
        bundle = await context.repository.stageArtifactBundle(runId, operationId, "query-pack", files);
        await validateStagedPack(context, runId, operationId, pack, files);
        if (options.signal?.aborted) throw cancelledBeforeCommit(runId, operationId);
        await context.repository.promoteArtifactBundle(runId, bundle);
        promoted = true;
      }
      await validateFinalPack(context, runId, pack);
      const finalState = { ...state, pack };
      await context.repository.commitState(runId, finalState, {
        operationId,
        idempotencyKey: `finalize:${runId}:${pack.pack_id}`,
        kind: "finalization",
        workflowPhase: "workflow_finalize",
        packId: pack.pack_id,
        stagedOperationId: operationId,
        referencedArtifacts: Object.values(pack.files).map((path) => `query-pack/${path}`),
      }, options);
      return pack;
    } catch (error: unknown) {
      const current = await context.repository.tryLoad(runId).catch(() => undefined);
      if (current?.pack?.pack_id !== pack.pack_id) {
        if (promoted) await context.repository.discardPromotedArtifactBundle(runId, "query-pack").catch(() => undefined);
        else await context.repository.discardArtifactBundle(runId, operationId).catch(() => undefined);
      }
      throw error;
    }
  });
}

function buildPack(
  context: CodeqlWorkflowContext,
  runId: string,
  state: Awaited<ReturnType<CodeqlWorkflowContext["repository"]["load"]>>,
  candidate: Awaited<ReturnType<CodeqlWorkflowContext["repository"]["load"]>>["candidates"][number],
  verification: Awaited<ReturnType<CodeqlWorkflowContext["repository"]["load"]>>["verifications"][number],
  packId: string,
): QueryPackManifest {
  const queryText = candidate.ql_text;
  const specText = `${JSON.stringify(state.spec, null, 2)}\n`;
  const verificationText = `${JSON.stringify(verification, null, 2)}\n`;
  const candidateText = `${JSON.stringify(candidate, null, 2)}\n`;
  return parseSchema(QueryPackManifestSchema, {
    schema_version: CONTRACTS_VERSION,
    pack_id: packId,
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
}

function packFiles(
  state: Awaited<ReturnType<CodeqlWorkflowContext["repository"]["load"]>>,
  candidate: Awaited<ReturnType<CodeqlWorkflowContext["repository"]["load"]>>["candidates"][number],
  verification: Awaited<ReturnType<CodeqlWorkflowContext["repository"]["load"]>>["verifications"][number],
  pack: QueryPackManifest,
): ArtifactBundleFile[] {
  const queryText = candidate.ql_text;
  const specText = `${JSON.stringify(state.spec, null, 2)}\n`;
  const verificationText = `${JSON.stringify(verification, null, 2)}\n`;
  const candidateText = `${JSON.stringify(candidate, null, 2)}\n`;
  const files: ArtifactBundleFile[] = [
    { relativePath: "query.ql", content: queryText },
    { relativePath: "candidate.json", content: candidateText },
    { relativePath: "spec.json", content: specText },
    { relativePath: "verification.json", content: verificationText },
    { relativePath: "qlpack.yml", content: candidate.qlpack_yml ?? qlpackForLanguage(state.spec.language) },
    { relativePath: "evidence.json", content: `${JSON.stringify({ schema_version: CONTRACTS_VERSION, run_id: pack.run_id, candidate_id: candidate.candidate_id, vulnerable: verification.vulnerable, fixed: verification.fixed, diagnostics: verification.diagnostics }, null, 2)}\n` },
    { relativePath: "REPRODUCE.md", content: reproduceText(state.spec.vulnerable_database.path, state.spec.fixed_database?.path) },
    { relativePath: "query-pack-manifest.json", content: `${JSON.stringify(pack, null, 2)}\n` },
  ];
  if (candidate.intent !== undefined) {
    files.push({ relativePath: "exact.ql", content: queryText }, { relativePath: "intent.json", content: `${JSON.stringify(candidate.intent, null, 2)}\n` });
  }
  if (candidate.probe_evidence !== undefined) files.push({ relativePath: "probe-evidence.json", content: `${JSON.stringify(candidate.probe_evidence, null, 2)}\n` });
  return files;
}

async function readExistingPack(context: CodeqlWorkflowContext, runId: string, expectedPackId: string): Promise<QueryPackManifest | undefined> {
  const raw = await context.repository.readArtifact(runId, "query-pack/query-pack-manifest.json");
  if (raw === undefined) {
    const existingPaths = await context.repository.listArtifactPaths(runId, "query-pack");
    if (existingPaths.length > 0) {
      await context.repository.discardPromotedArtifactBundle(runId, "query-pack").catch(() => undefined);
      throw new DomainError("ARTIFACT_CORRUPT", "artifact", "An incomplete Query Pack directory was found before finalization", false, { runId, paths: existingPaths.slice(0, 16) });
    }
    return undefined;
  }
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Existing Query Pack manifest is not valid JSON", false, { runId });
  }
  const pack = parseSchema(QueryPackManifestSchema, value, "query pack manifest");
  if (pack.pack_id !== expectedPackId) throw new DomainError("INVALID_STATE_TRANSITION", "state", "Existing Query Pack has a conflicting identity", false, { runId, expectedPackId, observedPackId: pack.pack_id });
  await validateFinalPack(context, runId, pack);
  return pack;
}

async function validateStagedPack(context: CodeqlWorkflowContext, runId: string, operationId: string, pack: QueryPackManifest, files: readonly ArtifactBundleFile[]): Promise<void> {
  const expected = new Map(files.map((file) => [file.relativePath, file.content]));
  for (const path of Object.values(pack.files)) {
    const content = await context.repository.readStagedArtifact(runId, operationId, path);
    if (content === undefined || content !== expected.get(path)) throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Staged Query Pack is incomplete or changed", false, { runId, operationId, path });
  }
  validatePackIntegrity(pack, expected);
}

async function validateFinalPack(context: CodeqlWorkflowContext, runId: string, pack: QueryPackManifest): Promise<void> {
  const contents = new Map<string, string>();
  for (const path of Object.values(pack.files)) {
    const content = await context.repository.readArtifact(runId, `query-pack/${path}`);
    if (content === undefined) throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Query Pack is incomplete", false, { runId, packId: pack.pack_id, path });
    contents.set(path, content);
  }
  validatePackIntegrity(pack, contents);
  const manifest = JSON.parse(contents.get(pack.files.manifest) ?? "null") as unknown;
  const parsed = parseSchema(QueryPackManifestSchema, manifest, "query pack manifest");
  if (parsed.pack_id !== pack.pack_id) throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Query Pack manifest identity does not match", false, { runId, packId: pack.pack_id });
}

function validatePackIntegrity(pack: QueryPackManifest, contents: ReadonlyMap<string, string>): void {
  const query = contents.get(pack.files.query);
  const candidate = contents.get(pack.files.candidate);
  const spec = contents.get(pack.files.spec);
  const verification = contents.get(pack.files.verification);
  if (query === undefined || candidate === undefined || spec === undefined || verification === undefined) throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Query Pack integrity inputs are incomplete", false, { packId: pack.pack_id });
  if (stableDigest(query) !== pack.integrity.query || stableDigest(candidate) !== pack.integrity.candidate || stableDigest(spec) !== pack.integrity.spec || stableDigest(verification) !== pack.integrity.verification) throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Query Pack integrity digest mismatch", false, { packId: pack.pack_id });
}

function cancelledBeforeCommit(runId: string, operationId: string): DomainError {
  return new DomainError("PROCESS_CANCELLED", "process", "Workflow operation was cancelled before the domain commit point", false, { runId, operationId, commitPointReached: false });
}

function reproduceText(vulnerableDatabase: string, fixedDatabase: string | undefined): string {
  return `# Reproduce\n\nRun from the Query Pack directory:\n\n\`codeql query compile query.ql --threads=1\`\n\n\`codeql database analyze <vulnerable_database> query.ql --rerun --format=sarif-latest --output=vulnerable.sarif --threads=1\`\n${fixedDatabase === undefined ? "" : "\n\`codeql database analyze <fixed_database> query.ql --rerun --format=sarif-latest --output=fixed.sarif --threads=1\`\n"}\nThe original vulnerable database path was: ${vulnerableDatabase}\n${fixedDatabase === undefined ? "No fixed database was provided.\n" : `The original fixed database path was: ${fixedDatabase}\n`}For relocated replay use: pure-auto-codeql query-pack verify <pack-dir> --vulnerable-db <path> [--fixed-db <path>]\nWhen the Query Pack and databases share a non-root directory, the CLI infers that directory as the trusted workspace. Use --workspace-root <path> when they are in separate locations.\n`;
}
