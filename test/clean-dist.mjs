import { rm } from "node:fs/promises";
import { resolve, sep } from "node:path";

const root = resolve(process.cwd());
const knownDistDirectories = [
  "packages/contracts/dist",
  "packages/core/dist",
  "packages/codeql-runner/dist",
  "packages/pi-extension/dist",
  "packages/cli/dist",
];

for (const relativePath of knownDistDirectories) {
  const directory = resolve(root, relativePath);
  if (directory !== root && !directory.startsWith(`${root}${sep}`)) {
    throw new Error(`Refusing to clean a path outside the workspace: ${relativePath}`);
  }
  await rm(directory, { recursive: true, force: true });
}
