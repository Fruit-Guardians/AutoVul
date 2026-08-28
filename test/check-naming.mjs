import { readFile } from "node:fs/promises";
import { join } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const trackedFiles = (await import("node:child_process")).execFileSync("git", ["ls-files", "-z"], { cwd: root }).toString("utf8").split("\0").filter(Boolean);
const historicalPrefixes = [
  "specs/changes/stabilize-architecture-boundaries/",
  "specs/changes/harden-workflow-commit-boundaries/",
  "specs/changes/rename-project-to-autovul/",
];
const stableRuleFiles = new Set([
  "packages/core/src/language-packs.ts",
  "packages/core/src/python-query-renderer.ts",
  "test/m2-real-kohya.case.json",
  "test/m3-golden-real.mjs",
  "test/m3-language-pack.test.ts",
  "test/m3-workflow.test.ts",
  "test/python-query-renderer.test.ts",
]);
const compatibilityFiles = new Set([
  "packages/cli/package.json",
  "packages/codeql-runner/src/environment.ts",
  "package-lock.json",
  "test/check-naming.mjs",
  "test/check-pack-output.mjs",
  "test/rename-compat.test.ts",
]);

const violations = [];
const allowed = [];
for (const file of trackedFiles) {
  if (file === "") continue;
  const contents = await readFile(join(root, file), "utf8");
  const lines = contents.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (!/pure.?auto.?codeql|PURE_AUTO_CODEQL/i.test(line)) continue;
    const category = allowCategory(file, line);
    if (category === undefined) {
      violations.push(`${file}:${index + 1}: ${line.trim()}`);
    } else {
      allowed.push(`${file}:${index + 1} [${category}]`);
    }
  }
}

if (violations.length > 0) {
  throw new Error(`Unapproved former-brand occurrences:\n${violations.join("\n")}`);
}
for (const item of allowed) console.log(`allowed former-brand occurrence ${item}`);
console.log(`naming check passed (${allowed.length} explicit compatibility/history occurrences)`);

function allowCategory(file, line) {
  if (historicalPrefixes.some((prefix) => file.startsWith(prefix))) return "historical-record";
  if (file === "test/check-naming.mjs") return "naming-governance";
  if (stableRuleFiles.has(file) && /pure-auto-codeql\/(?:[A-Za-z0-9._/-]+|\$\{[^}]+\})/.test(line)) return "stable-codeql-rule-id";
  if (compatibilityFiles.has(file) && /pure-auto-codeql-v2|PURE_AUTO_CODEQL_/i.test(line)) return "compatibility-surface";
  if (file === "README.md" && /pure-auto-codeql-v2|PURE_AUTO_CODEQL_/i.test(line)) return "compatibility-documentation";
  return undefined;
}
