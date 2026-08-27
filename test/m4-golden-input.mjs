import { readdir, readFile } from "node:fs/promises";
import { extname, relative, resolve } from "node:path";

const DEFAULT_MAX_FILES = 64;
const DEFAULT_MAX_FILE_BYTES = 16_000;
const DEFAULT_MAX_TOTAL_BYTES = 120_000;
const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  "build",
  "dist",
  "node_modules",
  "runs",
  "target",
  "vendor",
  "__pycache__",
]);

const EXTENSIONS_BY_LANGUAGE = {
  python: new Set([".py"]),
  javascript: new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]),
  typescript: new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]),
  java: new Set([".java", ".kt", ".kts"]),
  kotlin: new Set([".java", ".kt", ".kts"]),
  cpp: new Set([".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"]),
  c: new Set([".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"]),
};

/**
 * Build bounded, deterministic context for an external model wrapper.
 * Only vulnerable project source is read; fixed source and CodeQL artifacts
 * remain outside the model input.
 */
export async function buildSourceContext(root, language, options = {}) {
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const maxTotalBytes = options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;
  const extensions = EXTENSIONS_BY_LANGUAGE[language] ?? new Set();
  const files = [];
  const candidates = [];

  await collectFiles(resolve(root), resolve(root), extensions, candidates);
  candidates.sort((left, right) => left.localeCompare(right));

  let totalBytes = 0;
  let truncatedFiles = 0;
  for (const absolutePath of candidates) {
    if (files.length >= maxFiles || totalBytes >= maxTotalBytes) break;
    const bytes = await readFile(absolutePath);
    const available = Math.min(maxFileBytes, maxTotalBytes - totalBytes);
    if (available <= 0) break;
    const selected = bytes.subarray(0, available);
    const truncated = selected.length < bytes.length;
    if (truncated) truncatedFiles += 1;
    files.push({
      path: relative(resolve(root), absolutePath).split("\\").join("/"),
      content: selected.toString("utf8"),
      truncated,
    });
    totalBytes += selected.length;
  }

  return {
    root: resolve(root),
    language,
    files,
    truncated_files: truncatedFiles,
    total_bytes: totalBytes,
  };
}

async function collectFiles(root, directory, extensions, output) {
  const entries = (await readdir(directory, { withFileTypes: true }))
    .sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    if (entry.name.startsWith(".") && entry.name !== ".env") continue;
    if (entry.isDirectory()) {
      if (!IGNORED_DIRECTORIES.has(entry.name)) {
        await collectFiles(root, `${directory}/${entry.name}`, extensions, output);
      }
      continue;
    }
    if (!entry.isFile() || !extensions.has(extname(entry.name).toLowerCase())) continue;
    output.push(`${directory}/${entry.name}`);
  }
}
