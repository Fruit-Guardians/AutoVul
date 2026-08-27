import { readdir, readFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
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
    if (file.includes(`${join("packages", "codeql-runner", "src", "lsp", "lab")}${process.platform === "win32" ? "\\" : "/"}`)) continue;
    const lines = (await readFile(file, "utf8")).split(/\r?\n/).length - 1;
    if (lines > 1_000) oversized.push(`${relative(root, file)} (${lines} lines)`);
  }
}
if (oversized.length > 0) throw new Error(`Oversized hand-written production files:\n${oversized.join("\n")}`);

await assertAtMost("packages/core/src/query-workflow.ts", 400);
await assertAtMost("packages/pi-extension/src/index.ts", 150);
const facade = await readFile(join(root, "packages/core/src/query-workflow.ts"), "utf8");
if (facade.includes("query-workflow-policy")) throw new Error("query-workflow.ts still depends on the removed mixed policy collection");
const runnerEntry = await readFile(join(root, "packages/codeql-runner/src/index.ts"), "utf8");
if (runnerEntry.includes("CodeqlLspProtocolSpike") || runnerEntry.includes("protocol-spike")) throw new Error("protocol spike leaked into the production runner export surface");

console.log("Architecture check passed: production size and boundary checks are clean; protocol lab is isolated under codeql-runner/lab.");

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
