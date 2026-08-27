/**
 * Diagnostic-only generator for the Python command-injection fixture.
 *
 * This intentionally is not a model and must never be used with
 * PURE_AUTO_CODEQL_M4_GENERATOR_MODE=counted. It exists to exercise the real
 * probe, LSP draft, CodeQL CLI, and relocated Query Pack path while a model
 * provider is unavailable.
 */
const input = JSON.parse(await readStdin());
const files = input?.source_context?.files;
const vulnerableSource = Array.isArray(files)
  ? files.find((file) => file?.path?.endsWith("/app.py") && typeof file.content === "string")
  : undefined;
if (input?.language !== "python" || vulnerableSource === undefined
  || !/os\.getenv\s*\(/.test(vulnerableSource.content)
  || !/os\.system\s*\(/.test(vulnerableSource.content)) {
  throw new Error("DIAGNOSTIC_WRAPPER_SOURCE_PATTERN_NOT_FOUND");
}

const run = Number.isInteger(input.run) ? input.run : 1;
const round = Number.isInteger(input.round) ? input.round : 1;
process.stdout.write(JSON.stringify({
  candidate: {
    candidate_id: `diagnostic-python-${run}-r${round}`,
    query_id: `diagnostic-python-command-injection-${run}-r${round}`,
    intent: {
      schema_version: "v2.contracts/1",
      intent_id: "diagnostic-python-command-injection",
      language: "python",
      cwe: "CWE-078",
      query_kind: "path-problem",
      flow_mode: "taint",
      source: { kind: "environment", name: "getenv" },
      sink: { kind: "call", module: "os", member: "system", argument_index: 0 },
      message: "Environment-controlled command reaches os.system.",
    },
    rationale: "Diagnostic wrapper matched the supplied vulnerable source context.",
  },
  metadata: {
    provider: "diagnostic-fixture",
    model: "deterministic-source-pattern",
    adapter_version: "m4-diagnostic/1",
    parameters: { source_pattern: "python-os-getenv-to-system" },
    usage: { input_tokens: 0, output_tokens: 0, total_tokens: 0 },
  },
}));

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}
