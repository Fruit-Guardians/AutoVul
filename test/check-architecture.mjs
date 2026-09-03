import { readdir, readFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const typestateSpec = await readFile(join(root, "specs", "changes", "admit-typestate-capability-v1", "SPEC.md"), "utf8");
if (!/^- Status: (Accepted|Implemented|Verified|Archived)$/m.test(typestateSpec)) {
  throw new Error("Typestate production code requires an Accepted or later admit-typestate-capability-v1 SPEC");
}
const productionRoots = [
  "packages/contracts/src",
  "packages/core/src",
  "packages/codeql-runner/src",
  "packages/pi-extension/src",
  "packages/cli/src",
];
const oversized = [];
for (const relativeRoot of productionRoots) {
  for (const file of await sourceFiles(join(root, relativeRoot))) {
    const lines = (await readFile(file, "utf8")).split(/\r?\n/).length - 1;
    if (lines > 1_000) oversized.push(`${relative(root, file)} (${lines} lines)`);
  }
}
if (oversized.length > 0) throw new Error(`Oversized hand-written production files:\n${oversized.join("\n")}`);

await assertAtMost("packages/core/src/query-workflow.ts", 400);
await assertAtMost("packages/pi-extension/src/index.ts", 150);
await assertAtMost("packages/codeql-runner/src/query-runner.ts", 600);
await assertAtMost("packages/codeql-runner/src/query-sarif.ts", 250);
await assertAtMost("packages/codeql-runner/src/change-observation-git-adapter.ts", 500);
await assertAtMost("packages/codeql-runner/src/change-observation-parser.ts", 400);
const facade = await readFile(join(root, "packages/core/src/query-workflow.ts"), "utf8");
if (facade.includes("query-workflow-policy")) throw new Error("query-workflow.ts still depends on the removed mixed policy collection");
const runnerEntry = await readFile(join(root, "packages/codeql-runner/src/index.ts"), "utf8");
if (runnerEntry.includes("CodeqlLspProtocolSpike") || runnerEntry.includes("protocol-spike")) throw new Error("protocol spike leaked into the production runner export surface");

const contractsIndex = await readFile(join(root, "packages/contracts/src/index.ts"), "utf8");
if (!contractsIndex.includes('from "./research.js"')) throw new Error("shared research envelopes must be exported from contracts/src/research.ts");
const flowContracts = await readFile(join(root, "packages/contracts/src/flow.ts"), "utf8");
if (flowContracts.includes("export const ResearchActionSchema")) throw new Error("shared research envelopes must not be defined inside the Flow-specific module");
const researchRun = await readFile(join(root, "packages/core/src/research-run.ts"), "utf8");
if (/decideFlow|readFlowRunArtifact|FLOW_RESULT_ARTIFACT/.test(researchRun)) {
  throw new Error("the shared research run service must route capability replay without interpreting Flow artifacts or decisions");
}
const operationRoute = await readFile(join(root, "packages/core/src/research-operation.ts"), "utf8");
if (!operationRoute.includes("ResearchOperationRouteSchema")) throw new Error("shared operation routing metadata must have a contracts schema");
const flowService = await readFile(join(root, "packages/core/src/flow/service.ts"), "utf8");
if (!flowService.includes("stageArtifactBundle") || !flowService.includes("promoteArtifactBundle") || flowService.includes("writeArtifact(runId, FLOW_RESULT_ARTIFACT")) {
  throw new Error("Flow result and shared route must be committed as one staged artifact bundle");
}
const missingCheckService = await readFile(join(root, "packages/core/src/missing-check/service.ts"), "utf8");
if (/FlowModel|FlowEndpoint|FlowDecision|decideFlow/.test(missingCheckService)) {
  throw new Error("MissingCheck must not reuse Flow domain types or decision semantics");
}
const application = await readFile(join(root, "packages/core/src/application.ts"), "utf8");
if (!application.includes("MissingCheckResearchService") || !application.includes('capability === "missing_check"')) {
  throw new Error("Application must route the accepted MissingCheck branch explicitly");
}
const cli = await readFile(join(root, "packages/cli/src/cli.ts"), "utf8");
if (!cli.includes("application.research") || !cli.includes("application.manageRun")) {
  throw new Error("CLI must route aggregate research and run commands through the shared Application API");
}
const legacyProjection = await readFile(join(root, "packages/core/src/flow/legacy-projection.ts"), "utf8");
if (!legacyProjection.includes("projectTaintIntentToFlow") || !legacyProjection.includes("decideFlow")) {
  throw new Error("legacy CodeQL compatibility must project through the Flow normalizer and Core decision policy");
}
const coreFiles = await sourceFiles(join(root, "packages/core/src"));
for (const file of coreFiles) {
  const text = await readFile(file, "utf8");
  if (/export class CapabilityRegistry|class CapabilityPluginLoader/.test(text)) {
    throw new Error(`Capability registry or plugin loader is forbidden until a second real paradigm exists: ${relative(root, file)}`);
  }
}
for (const relativeRoot of productionRoots) {
  for (const file of await sourceFiles(join(root, relativeRoot))) {
    const text = await readFile(file, "utf8");
    if (/\b(?:DeltaHypothesis|DeltaDecision|VariantHypothesis|VariantDecision)\b/.test(text)) {
      throw new Error(`Unadmitted Capability domain type or route leaked into production code: ${relative(root, file)}`);
    }
  }
}
for (const forbidden of ["missingcheck", "delta", "variant"]) {
  const path = join(root, "packages/core/src", forbidden);
  try {
    await readdir(path);
    throw new Error(`placeholder Capability module exists at ${relative(root, path)}`);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") continue;
    throw error;
  }
}

console.log("Architecture check passed: production and LSP lab size/boundary checks are clean; protocol lab is isolated under codeql-runner/lab.");

async function assertAtMost(relativePath, maximum) {
  const file = join(root, relativePath);
  const lines = (await readFile(file, "utf8")).split(/\r?\n/).length - 1;
  if (lines > maximum) throw new Error(`${relativePath} is ${lines} lines; maximum is ${maximum}`);
}

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const result = [];
  for (const entry of entries) {
    const file = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await sourceFiles(file));
    else if (entry.name.endsWith(".ts")) result.push(file);
  }
  return result;
}
