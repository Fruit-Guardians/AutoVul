import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runL0Matrix } from "./l0-lsp-matrix.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const outputPath = process.env.CODEQL_L0_SNAPSHOT ?? resolve(repositoryRoot, "plan", "l0-codeql-lsp-capability-snapshot.json");

export async function runL0Snapshot() {
  let snapshot;
  try {
    snapshot = await runL0Matrix();
  } catch (error) {
    snapshot = {
      schemaVersion: "v2.l0.codeql-lsp-matrix/1",
      generatedAt: new Date().toISOString(),
      runnerError: error instanceof Error ? error.message : String(error),
      scenarios: [],
      summary: { scenarioCount: 0, runnerErrors: 1 },
    };
  }
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
  console.log(JSON.stringify({ snapshot: outputPath, summary: snapshot.summary, runnerError: snapshot.runnerError }, null, 2));
  return snapshot;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runL0Snapshot();
}
