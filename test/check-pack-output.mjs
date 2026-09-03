import { spawnSync } from "node:child_process";

const packages = [
  "@autovul/contracts",
  "@autovul/core",
  "@autovul/codeql-runner",
  "@autovul/pi-extension",
  "@autovul/deepseek-harness",
  "@autovul/cli",
];
const result = spawnSync("npm", ["pack", "--dry-run", "--json", ...packages.flatMap((name) => ["--workspace", name])], {
  cwd: process.cwd(),
  encoding: "utf8",
});
if (result.status !== 0) {
  process.stderr.write(result.stderr || result.stdout || "npm pack failed\n");
  process.exit(result.status ?? 1);
}

let entries;
try {
  entries = JSON.parse(result.stdout);
} catch (error) {
  throw new Error(`npm pack --json returned invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
}
const packageNames = entries.map((entry) => entry.name).sort();
const expectedPackageNames = [...packages].sort();
if (JSON.stringify(packageNames) !== JSON.stringify(expectedPackageNames)) {
  throw new Error(`Unexpected workspace package output: ${packageNames.join(", ")}`);
}
const cliPackage = JSON.parse(await (await import("node:fs/promises")).readFile(new URL("../packages/cli/package.json", import.meta.url), "utf8"));
if (JSON.stringify(cliPackage.bin) !== JSON.stringify({ autovul: "./dist/main.js", "pure-auto-codeql-v2": "./dist/main.js" })) {
  throw new Error("CLI package must expose the canonical autovul binary and its compatibility alias");
}
const notices = entries.flatMap((entry) => entry.files ?? []).map((file) => file.path).filter((path) => typeof path === "string");
const legacy = notices.filter((path) => /^dist\/lsp\/protocol-spike\.(js|d\.ts|js\.map|d\.ts\.map)$/.test(path));
const lab = notices.filter((path) => /^dist\/lsp\/lab\/protocol-spike\.(js|d\.ts|js\.map|d\.ts\.map)$/.test(path));
if (legacy.length > 0) {
  throw new Error(`Stale legacy LSP output is present in a package: ${legacy.join(", ")}`);
}
if (lab.length > 0 && !notices.some((path) => path === "dist/lsp/lab/index.js")) {
  throw new Error("LSP lab protocol output is present without its approved lab entry point");
}
console.log(`pack output clean (${entries.length} packages)`);
