import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const rootSpecPath = join(root, "SPEC.md");
const changesRoot = join(root, "specs", "changes");
const allowedStatuses = new Set(["Draft", "Accepted", "Implemented", "Verified", "Archived"]);
const requirementPattern = /^- `(REQ-[A-Z0-9]+(?:-[A-Z0-9]+)+)`:/gm;

const rootSpec = await readFile(rootSpecPath, "utf8");
assertIncludes(rootSpec, "- Status:", "SPEC.md must declare a Status");
assertIncludes(rootSpec, "- Version:", "SPEC.md must declare a Version");
assertIncludes(rootSpec, "## 12. Change control", "SPEC.md must define change control");

const rootRequirements = collectRequirements(rootSpec);
if (rootRequirements.length === 0) {
  fail("SPEC.md must contain numbered requirements");
}
assertUnique(rootRequirements, "SPEC.md contains duplicate requirement IDs");

const entries = await readdir(changesRoot, { withFileTypes: true });
for (const entry of entries) {
  if (!entry.isDirectory()) continue;
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(entry.name)) {
    fail(`Invalid change id ${entry.name}; use lowercase kebab-case`);
  }

  const path = join(changesRoot, entry.name, "SPEC.md");
  let content;
  try {
    content = await readFile(path, "utf8");
  } catch {
    fail(`Change ${entry.name} must contain SPEC.md`);
  }

  const declaredId = matchMetadata(content, "Change ID");
  if (declaredId.replaceAll("`", "") !== entry.name) {
    fail(`Change ${entry.name} declares mismatched Change ID ${declaredId}`);
  }

  const status = matchMetadata(content, "Status");
  if (!allowedStatuses.has(status)) {
    fail(`Change ${entry.name} has invalid Status ${status}`);
  }

  const requirements = collectRequirements(content);
  if (requirements.length === 0) {
    fail(`Change ${entry.name} must contain numbered requirements`);
  }
  assertUnique(requirements, `Change ${entry.name} contains duplicate requirement IDs`);

  if (status !== "Draft" && /<[^>]+>|YYYY-MM-DD|\.\.\./.test(content)) {
    fail(`Non-draft change ${entry.name} still contains template placeholders`);
  }
}

console.log(`SPEC check passed: ${rootRequirements.length} baseline requirements, ${entries.filter((entry) => entry.isDirectory()).length} active change specs`);

function collectRequirements(content) {
  return [...content.matchAll(requirementPattern)].map((match) => match[1]);
}

function matchMetadata(content, key) {
  const match = content.match(new RegExp(`^- ${key}:\\s*(.+)$`, "m"));
  if (match?.[1] === undefined) fail(`Missing metadata: ${key}`);
  return match[1].trim();
}

function assertIncludes(content, expected, message) {
  if (!content.includes(expected)) fail(message);
}

function assertUnique(values, message) {
  const seen = new Set();
  const duplicates = new Set();
  for (const value of values) {
    if (seen.has(value)) duplicates.add(value);
    seen.add(value);
  }
  if (duplicates.size > 0) fail(`${message}: ${[...duplicates].join(", ")}`);
}

function fail(message) {
  throw new Error(message);
}
