import {
  asDomainError,
  DomainError,
  parseSchema,
  QueryCandidateSchema,
  TaintQueryIntentSchema,
  QueryPackManifestSchema,
  VulnerabilitySpecSchema,
  stableDigest,
} from "@autovul/contracts";
import { createLocalApplication, readAutovulEnv, type LocalApplicationOptions } from "@autovul/codeql-runner";
import type { ApplicationApi } from "@autovul/core";
import { cp, readFile } from "node:fs/promises";
import { realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";

export interface CliIo {
  readonly stdout: (value: string) => void;
  readonly stderr: (value: string) => void;
}

interface ParsedCli {
  readonly command: string | undefined;
  readonly positional: readonly string[];
  readonly json: boolean;
  readonly runsDir: string | undefined;
  readonly codeqlPath: string | undefined;
  readonly workspaceRoot: string | undefined;
  readonly timeoutMs: number | undefined;
  readonly values: Readonly<Record<string, string>>;
}

const defaultIo: CliIo = {
  stdout: (value) => process.stdout.write(value),
  stderr: (value) => process.stderr.write(value),
};

export async function runCli(argv: readonly string[], io: CliIo = defaultIo): Promise<number> {
  let application: ApplicationApi | undefined;
  try {
    const parsed = parseArguments(argv);
    const runsDir = parsed.runsDir ?? readAutovulEnv("RUNS_DIR");
    const inferredWorkspaceRoot = parsed.workspaceRoot === undefined
      ? await inferQueryPackWorkspaceRoot(parsed)
      : undefined;
    const workspaceRoot = parsed.workspaceRoot ?? inferredWorkspaceRoot;
    const applicationOptions: LocalApplicationOptions = {
      ...(runsDir === undefined ? {} : { runsDir }),
      ...(parsed.codeqlPath === undefined ? {} : { codeqlPath: parsed.codeqlPath }),
      ...(workspaceRoot === undefined ? {} : { workspaceRoot }),
      ...(parsed.timeoutMs === undefined ? {} : { timeoutMs: parsed.timeoutMs }),
    };
    application = createLocalApplication(applicationOptions);
    const result = await execute(parsed, application);
    writeResult(io, parsed.json, { ok: true, result });
    return 0;
  } catch (error: unknown) {
    const domainError = asDomainError(error);
    const json = argv.includes("--json");
    writeResult(io, json, { ok: false, error: domainError.toRecord() });
    return 1;
  } finally {
    await application?.close();
  }
}

function parseArguments(argv: readonly string[]): ParsedCli {
  let json = false;
  let runsDir: string | undefined;
  let codeqlPath: string | undefined;
  let workspaceRoot: string | undefined;
  let timeoutMs: number | undefined;
  const values: Record<string, string> = {};
  const positional: string[] = [];

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === undefined) {
      continue;
    }
    if (argument === "--json") {
      json = true;
      continue;
    }
    if (
      argument === "--runs-dir" || argument === "--codeql" || argument === "--workspace-root" || argument === "--timeout-ms"
      || argument === "--spec" || argument === "--candidate" || argument === "--query-file"
      || argument === "--candidate-id" || argument === "--query-id" || argument === "--spec-id"
      || argument === "--round" || argument === "--origin" || argument === "--output"
      || argument === "--vulnerable-db" || argument === "--fixed-db" || argument === "--intent" || argument === "--request"
    ) {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) {
        throw new DomainError("INVALID_INPUT", "input", `${argument} requires a value`, false, { argument });
      }
      index += 1;
      if (argument === "--runs-dir") {
        runsDir = value;
      } else if (argument === "--codeql") {
        codeqlPath = value;
      } else if (argument === "--workspace-root") {
        workspaceRoot = value;
      } else if (argument === "--timeout-ms") {
        const parsed = Number(value);
        if (!Number.isInteger(parsed) || parsed <= 0) {
          throw new DomainError("INVALID_INPUT", "input", "--timeout-ms must be a positive integer", false, { value });
        }
        timeoutMs = parsed;
      }
      values[argument.slice(2)] = value;
      continue;
    }
    if (argument.startsWith("--")) {
      throw new DomainError("INVALID_INPUT", "input", `Unknown option: ${argument}`, false, { argument });
    }
    positional.push(argument);
  }

  return {
    command: positional[0],
    positional: positional.slice(1),
    json,
    runsDir,
    codeqlPath,
    workspaceRoot,
    timeoutMs,
    values,
  };
}

async function execute(parsed: ParsedCli, application: ApplicationApi): Promise<unknown> {
  if (parsed.command === "doctor" && parsed.positional.length === 0) {
    return application.doctor();
  }
  if (parsed.command === "database" && parsed.positional.length === 2 && parsed.positional[0] === "inspect") {
    const path = parsed.positional[1];
    if (path !== undefined) {
      return application.databaseInspect(path);
    }
  }
  if (parsed.command === "database" && parsed.positional.length === 2 && parsed.positional[0] === "validate") {
    const path = parsed.positional[1];
    if (path !== undefined) {
      return application.databaseValidate(path);
    }
  }
  if (parsed.command === "status" && parsed.positional.length === 1) {
    const runId = parsed.positional[0];
    if (runId !== undefined) {
      return application.status(runId);
    }
  }
  if (parsed.command === "resume" && parsed.positional.length === 1) {
    const runId = parsed.positional[0];
    if (runId !== undefined) {
      return application.resume(runId);
    }
  }
  if (parsed.command === "research" && (parsed.positional[0] === "validate" || parsed.positional[0] === "execute") && parsed.positional.length === 1) {
    const requestPath = parsed.values.request;
    if (requestPath === undefined) throw new DomainError("INVALID_INPUT", "input", "research requires --request <json-file>", false);
    const request = await readJsonFile(requestPath, "autovul research request");
    if (typeof request !== "object" || request === null || Array.isArray(request)) throw new DomainError("INVALID_INPUT", "input", "research request must be a JSON object", false);
    const action = parsed.positional[0];
    return application.research({ ...(request as Record<string, unknown>), action });
  }
  if (parsed.command === "run" && (parsed.positional[0] === "status" || parsed.positional[0] === "cancel" || parsed.positional[0] === "replay") && parsed.positional.length === 2) {
    const runId = parsed.positional[1];
    const action = parsed.positional[0];
    if (runId !== undefined) {
      return application.manageRun({ action, run_id: runId });
    }
  }
  if (parsed.command === "workflow" && parsed.positional[0] === "start" && parsed.positional.length === 1) {
    const specPath = parsed.values.spec;
    if (specPath === undefined) {
      throw new DomainError("INVALID_INPUT", "input", "workflow start requires --spec <json-file>", false);
    }
    return application.workflowStart(await readJsonFile(specPath, "vulnerability spec"));
  }
  if (parsed.command === "workflow" && parsed.positional[0] === "status" && parsed.positional.length === 2) {
    const runId = parsed.positional[1];
    if (runId !== undefined) {
      return application.workflowStatus(runId);
    }
  }
  if (parsed.command === "workflow" && parsed.positional[0] === "finalize" && parsed.positional.length === 2) {
    const runId = parsed.positional[1];
    if (runId !== undefined) {
      const pack = await application.workflowFinalize(runId);
      const outputPath = parsed.values.output;
      if (outputPath !== undefined) {
        const run = await application.status(runId);
        await cp(`${run.artifactRoot}/query-pack`, outputPath, { recursive: true, force: true });
      }
      return pack;
    }
  }
  if (parsed.command === "query" && parsed.positional[0] === "probe" && parsed.positional.length === 2) {
    const runId = parsed.positional[1];
    const intentPath = parsed.values.intent;
    if (runId !== undefined && intentPath !== undefined) {
      return application.queryProbe(runId, parseSchema(TaintQueryIntentSchema, await readJsonFile(intentPath, "taint query intent"), "taint query intent"));
    }
    throw new DomainError("INVALID_INPUT", "input", "query probe requires --intent <json-file>", false);
  }
  if (parsed.command === "query" && parsed.positional[0] === "draft" && parsed.positional.length === 2) {
    const runId = parsed.positional[1];
    const candidatePath = parsed.values.candidate;
    if (runId !== undefined && candidatePath !== undefined) {
      return application.queryDraft(runId, await readJsonFile(candidatePath, "query candidate"));
    }
    throw new DomainError("INVALID_INPUT", "input", "query draft requires --candidate <json-file>", false);
  }
  if (parsed.command === "query" && parsed.positional[0] === "verify" && parsed.positional.length === 2) {
    const runId = parsed.positional[1];
    if (runId !== undefined) {
      const candidatePath = parsed.values.candidate;
      if (candidatePath !== undefined) {
        return application.queryVerify(runId, await readJsonFile(candidatePath, "query candidate"));
      }
      const queryPath = parsed.values["query-file"];
      const candidateId = parsed.values["candidate-id"];
      if (queryPath === undefined || candidateId === undefined) {
        throw new DomainError("INVALID_INPUT", "input", "query verify requires --candidate <json-file> or --query-file plus --candidate-id", false);
      }
      const workflow = await application.workflowStatus(runId);
      const qlText = await readTextFile(queryPath, "query file");
      const round = parsed.values.round === undefined ? 1 : Number(parsed.values.round);
      if (!Number.isInteger(round) || round < 1 || round > 3) {
        throw new DomainError("INVALID_INPUT", "input", "--round must be an integer from 1 to 3", false);
      }
      const queryId = parsed.values["query-id"] ?? candidateId;
      const specId = parsed.values["spec-id"] ?? workflow.spec.spec_id;
      return application.queryVerify(runId, {
        schema_version: "v2.contracts/1",
        candidate_id: candidateId,
        query_id: queryId,
        spec_id: specId,
        language: workflow.spec.language,
        ql_text: qlText,
        round,
        origin: parsed.values.origin === "pi_generated" || parsed.values.origin === "pi_revised" || parsed.values.origin === "test"
          ? parsed.values.origin
          : "cli",
      });
    }
  }
  if (parsed.command === "query-pack" && parsed.positional[0] === "verify" && parsed.positional.length === 2) {
    const packPath = parsed.positional[1];
    if (packPath === undefined) {
      throw new DomainError("INVALID_INPUT", "input", "query-pack verify requires a pack directory", false);
    }
    return verifyRelocatedPack(packPath, parsed, application);
  }
  throw new DomainError("INVALID_INPUT", "input", "Usage: doctor | database inspect <path> | status <run-id> | research validate --request <file> | research execute --request <file> (including a change_observation service request) | run status <run-id> | run cancel <run-id> | run replay <run-id> | workflow start --spec <file> | query probe <run-id> --intent <file> | query draft <run-id> --candidate <file> | query verify <run-id> --candidate <file> | query-pack verify <pack-dir> --vulnerable-db <path> [--fixed-db <path>] | workflow status <run-id> | workflow finalize <run-id> [--output <dir>]", false);
}

async function verifyRelocatedPack(packPath: string, parsed: ParsedCli, application: ApplicationApi): Promise<unknown> {
  const root = resolve(packPath);
  const manifest = parseSchema(QueryPackManifestSchema, await readJsonFile(packFile(root, "query-pack-manifest.json"), "query pack manifest"), "query pack manifest");
  const queryPath = packFile(root, manifest.files.query);
  const candidatePath = packFile(root, manifest.files.candidate);
  const specPath = packFile(root, manifest.files.spec);
  const verificationPath = packFile(root, manifest.files.verification);
  const queryText = await readTextFile(queryPath, "query pack query");
  const candidateText = await readTextFile(candidatePath, "query pack candidate");
  const specText = await readTextFile(specPath, "query pack spec");
  const verificationText = await readTextFile(verificationPath, "query pack verification");
  if (stableDigest(queryText) !== manifest.integrity.query
    || stableDigest(candidateText) !== manifest.integrity.candidate
    || stableDigest(specText) !== manifest.integrity.spec
    || stableDigest(verificationText) !== manifest.integrity.verification) {
    throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Query Pack integrity verification failed", false, { packPath: root });
  }
  const candidate = parseSchema(QueryCandidateSchema, JSON.parse(candidateText) as unknown, "query pack candidate");
  if (candidate.ql_text !== queryText) {
    throw new DomainError("ARTIFACT_CORRUPT", "artifact", "Query Pack candidate and query.ql disagree", false, { packPath: root });
  }
  const originalSpec = parseSchema(VulnerabilitySpecSchema, JSON.parse(specText) as unknown, "query pack spec");
  const vulnerablePath = parsed.values["vulnerable-db"] ?? originalSpec.vulnerable_database.path;
  const fixedPath = parsed.values["fixed-db"];
  const spec = {
    ...originalSpec,
    vulnerable_database: { ...originalSpec.vulnerable_database, path: vulnerablePath },
    ...(fixedPath === undefined
      ? {}
      : { fixed_database: { ...(originalSpec.fixed_database ?? { language: originalSpec.language }), path: fixedPath } }),
  };
  const started = await application.workflowStart(spec);
  const verification = await application.queryVerify(started.run.runId, candidate);
  if (!verification.passed) {
    throw new DomainError("QUERY_RESULT_MISMATCH", "policy", "Relocated Query Pack replay did not pass", false, {
      runId: started.run.runId,
      diagnostics: verification.diagnostics,
    });
  }
  const pack = await application.workflowFinalize(started.run.runId);
  return { run_id: started.run.runId, verification, pack, replay: { relocated: true, source_pack: root } };
}

async function inferQueryPackWorkspaceRoot(parsed: ParsedCli): Promise<string | undefined> {
  if (parsed.command !== "query-pack" || parsed.positional[0] !== "verify") {
    return undefined;
  }
  const packPath = parsed.positional[1];
  if (packPath === undefined) {
    return undefined;
  }
  try {
    const packRoot = resolve(packPath);
    const originalSpec = JSON.parse(await readFile(joinPath(packRoot, "spec.json"), "utf8")) as {
      vulnerable_database?: { path?: unknown };
      fixed_database?: { path?: unknown };
    };
    const databasePaths = [
      parsed.values["vulnerable-db"] ?? originalSpec.vulnerable_database?.path,
      parsed.values["fixed-db"] ?? originalSpec.fixed_database?.path,
    ].filter((value): value is string => typeof value === "string" && value.length > 0);
    const paths = [packRoot, ...databasePaths];
    const canonicalPaths: string[] = [];
    for (const path of paths) {
      canonicalPaths.push(await realpath(path));
    }
    const workspaceRoot = canonicalPaths.reduce((ancestor, path) => commonAncestor(ancestor, path));
    return dirname(workspaceRoot) === workspaceRoot ? undefined : workspaceRoot;
  } catch {
    return undefined;
  }
}

function commonAncestor(left: string, right: string): string {
  let ancestor = left;
  while (!isWithin(ancestor, right)) {
    const parent = dirname(ancestor);
    if (parent === ancestor) return ancestor;
    ancestor = parent;
  }
  return ancestor;
}

function isWithin(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child === "" || (!child.startsWith("..") && !isAbsolute(child));
}

function joinPath(root: string, child: string): string {
  return resolve(root, child);
}

function packFile(root: string, relativePath: string): string {
  if (isAbsolute(relativePath)) {
    throw new DomainError("INVALID_INPUT", "input", "Query Pack file paths must be relative", false, { relativePath });
  }
  const path = resolve(root, relativePath);
  const inside = relative(root, path);
  if (inside === ".." || inside.startsWith(".." + "/") || isAbsolute(inside)) {
    throw new DomainError("INVALID_INPUT", "input", "Query Pack file path escapes the pack directory", false, { relativePath });
  }
  return path;
}

async function readJsonFile(path: string, label: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as unknown;
  } catch (error: unknown) {
    throw new DomainError("INVALID_INPUT", "input", `Cannot read ${label}`, false, {
      path,
      reason: error instanceof Error ? error.message : "invalid JSON",
    });
  }
}

async function readTextFile(path: string, label: string): Promise<string> {
  try {
    const value = await readFile(path, "utf8");
    if (value.length === 0) {
      throw new Error("file is empty");
    }
    return value;
  } catch (error: unknown) {
    throw new DomainError("INVALID_INPUT", "input", `Cannot read ${label}`, false, {
      path,
      reason: error instanceof Error ? error.message : "read failed",
    });
  }
}

function writeResult(io: CliIo, json: boolean, value: unknown): void {
  const output = JSON.stringify(value, null, json ? 2 : 2);
  io.stdout(`${output}\n`);
}
