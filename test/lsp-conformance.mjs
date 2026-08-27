import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const snapshotPath = process.env.CODEQL_L0_SNAPSHOT ?? resolve(repositoryRoot, "plan", "l0-codeql-lsp-capability-snapshot.json");
const snapshot = JSON.parse(await readFile(snapshotPath, "utf8"));
const failures = [];

if (snapshot.runnerError !== undefined) {
  failures.push(`snapshot runner failed: ${snapshot.runnerError}`);
}

const scenarios = snapshot.scenarios ?? [];
const baseline = scenarios.find(({ id }) => id === "baseline-async-active-initial-pack-roots");
if (baseline === undefined) {
  failures.push("required baseline scenario is missing");
} else {
  const capabilitySummary = baseline.snapshot?.capabilitySummary;
  for (const capability of ["diagnostics", "definition", "hover", "completion", "workspaceFolders", "dynamicWorkspaceFolders"]) {
    if (capabilitySummary?.[capability] !== true) {
      failures.push(`baseline capability missing: ${capability}`);
    }
  }
  for (const document of baseline.observations?.documents ?? []) {
    if (!document.validReceived || document.validDiagnostics !== 0) {
      failures.push(`${document.language}: baseline valid diagnostics are not clean`);
    }
    if (!document.invalidReceived || document.invalidDiagnostics === 0) {
      failures.push(`${document.language}: baseline invalid diagnostics did not prove an error notification`);
    }
    if (!document.definitionCompleted || document.definitionLocations.length === 0) {
      failures.push(`${document.language}: definition did not resolve to a location`);
    }
    if (!document.hoverCompleted || !document.hoverHasText) {
      failures.push(`${document.language}: hover did not return bounded content`);
    }
    if (!document.completionCompleted || document.completionItems === 0) {
      failures.push(`${document.language}: completion did not return effective items`);
    }
  }
}

for (const scenario of scenarios) {
  if (scenario.snapshot?.transport?.cleanShutdown !== true) {
    failures.push(`${scenario.id}: process cleanup was not clean`);
  }
}

const dynamic = scenarios.find(({ id }) => id === "workspace-add-dynamic");
if (dynamic === undefined) {
  failures.push("workspace-add-dynamic scenario is missing");
} else {
  const document = dynamic.observations?.documents?.[0];
  if (dynamic.snapshot?.workspace?.dynamicWorkspaceFolders?.length !== 1 || document?.validReceived !== true || document?.validDiagnostics !== 0 || document?.definitionLocations?.length === 0) {
    failures.push("dynamic workspace add did not produce clean diagnostics plus actual symbol resolution");
  }
}

const update = scenarios.find(({ id }) => id === "qlpack-update-watched");
if (update === undefined) {
  failures.push("qlpack-update-watched scenario is missing");
} else {
  const document = update.observations?.documents?.[0];
  if (update.snapshot?.workspace?.workspaceUpdates?.length === 0 || document?.validReceived !== true || document?.validDiagnostics !== 0 || document?.definitionLocations?.length === 0) {
    failures.push("qlpack update notification did not produce clean diagnostics plus actual symbol resolution");
  }
}

console.log(JSON.stringify({ snapshot: snapshotPath, failures, conformance: failures.length === 0 ? "passed" : "failed" }, null, 2));
if (failures.length > 0) {
  process.exitCode = 1;
}
