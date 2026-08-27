import { spawnSync } from "node:child_process";

const packages = [
  "@pure-auto-codeql/contracts",
  "@pure-auto-codeql/core",
  "@pure-auto-codeql/codeql-runner",
  "@pure-auto-codeql/pi-extension",
  "@pure-auto-codeql/cli",
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
