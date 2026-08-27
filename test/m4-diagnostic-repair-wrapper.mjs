/**
 * Diagnostic-only feedback-loop generator. It intentionally submits one
 * schema-valid but language-pack-invalid call matcher, then repairs it on the
 * next round after receiving the evaluator's probe feedback.
 */
const input = JSON.parse(await readStdin());
const source = input?.source_context?.files?.find((file) => file?.path?.endsWith("/app.py"));
if (input?.language !== "python" || typeof source?.content !== "string"
  || !/os\.getenv\s*\(/.test(source.content) || !/os\.system\s*\(/.test(source.content)) {
  throw new Error("DIAGNOSTIC_REPAIR_SOURCE_PATTERN_NOT_FOUND");
}

const round = Number.isInteger(input.round) ? input.round : 1;
const sink = round === 1
  ? { kind: "call" }
  : { kind: "call", module: "os", member: "system", argument_index: 0 };
process.stdout.write(JSON.stringify({
  candidate: {
    candidate_id: `diagnostic-repair-${round}`,
    query_id: `diagnostic-repair-${round}`,
    intent: {
      schema_version: "v2.contracts/1",
      intent_id: "diagnostic-python-command-injection-repair",
      language: "python",
      cwe: "CWE-078",
      query_kind: "path-problem",
      flow_mode: "taint",
      source: { kind: "environment", name: "getenv" },
      sink,
      message: "Environment-controlled command reaches os.system.",
    },
  },
  metadata: {
    provider: "diagnostic-fixture",
    model: "deterministic-repair-feedback",
    adapter_version: "m4-diagnostic-repair/1",
    parameters: { invalid_first_round: true },
    usage: { input_tokens: 0, output_tokens: 0, total_tokens: 0 },
  },
}));

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}
