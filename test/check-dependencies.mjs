import { readFile } from "node:fs/promises";
import { join } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const packageRoots = {
  contracts: "packages/contracts",
  core: "packages/core",
  "codeql-runner": "packages/codeql-runner",
  "pi-extension": "packages/pi-extension",
  cli: "packages/cli",
};

const forbiddenImports = {
  contracts: ["@pure-auto-codeql/", "@earendil-works/pi-", "node:"],
  core: ["@earendil-works/pi-", "node:"],
  "codeql-runner": ["@earendil-works/pi-"],
  cli: ["@earendil-works/pi-"],
};

const allowedInternal = {
  contracts: [],
  core: ["@pure-auto-codeql/contracts"],
  "codeql-runner": ["@pure-auto-codeql/contracts", "@pure-auto-codeql/core"],
  "pi-extension": [
    "@pure-auto-codeql/contracts",
    "@pure-auto-codeql/core",
    "@pure-auto-codeql/codeql-runner",
    "@earendil-works/pi-coding-agent",
  ],
  cli: ["@pure-auto-codeql/contracts", "@pure-auto-codeql/core", "@pure-auto-codeql/codeql-runner"],
};

for (const [name, relativeRoot] of Object.entries(packageRoots)) {
  const packageJson = JSON.parse(await readFile(join(root, relativeRoot, "package.json"), "utf8"));
  const declared = new Set([
    ...Object.keys(packageJson.dependencies ?? {}),
    ...Object.keys(packageJson.devDependencies ?? {}),
    ...Object.keys(packageJson.peerDependencies ?? {}),
  ]);
  for (const internal of allowedInternal[name]) {
    if (internal.startsWith("@pure-auto-codeql/") && !declared.has(internal)) {
      throw new Error(`${name} uses undeclared internal dependency ${internal}`);
    }
  }
  const sources = await readSourceFiles(join(root, relativeRoot, "src"));
  for (const source of sources) {
    const contents = await readFile(source, "utf8");
    for (const forbidden of forbiddenImports[name] ?? []) {
      if (contents.includes(`from "${forbidden}`) || contents.includes(`from '${forbidden}`)) {
        throw new Error(`${name} contains forbidden import ${forbidden}: ${source}`);
      }
    }
    for (const match of contents.matchAll(/from\s+["']([^"']+)["']/g)) {
      const imported = match[1];
      if (imported.startsWith("@pure-auto-codeql/") && !(allowedInternal[name] ?? []).includes(imported)) {
        throw new Error(`${name} has forbidden reverse dependency ${imported}: ${source}`);
      }
    }
    if (name !== "pi-extension" && /\bany\b/.test(contents)) {
      throw new Error(`${name} contains an explicit any type: ${source}`);
    }
  }
}

async function readSourceFiles(directory) {
  const entries = await (await import("node:fs/promises")).readdir(directory, { withFileTypes: true });
  const result = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      result.push(...await readSourceFiles(path));
    } else if (entry.name.endsWith(".ts")) {
      result.push(path);
    }
  }
  return result;
}
