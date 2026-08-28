import {
  fauxAssistantMessage,
  fauxProvider,
  fauxText,
  fauxToolCall,
} from "../node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/dist/index.js";

const vulnerableDatabase = required("AUTOVUL_PI_M4_VULNERABLE_DB");
const fixedDatabase = required("AUTOVUL_PI_M4_FIXED_DB");
const projectRoot = required("AUTOVUL_PI_M4_PROJECT_ROOT");
const specId = "pi-m4-python-command-injection";
const intent = {
  schema_version: "v2.contracts/1",
  intent_id: "pi-m4-python-command-injection",
  language: "python",
  cwe: "CWE-078",
  query_kind: "path-problem",
  flow_mode: "taint",
  source: { kind: "environment", name: "getenv" },
  sink: { kind: "call", module: "os", member: "system", argument_index: 0 },
  message: "Environment-controlled command reaches os.system.",
};
const spec = {
  schema_version: "v2.contracts/1",
  spec_id: specId,
  language: "python",
  cwe: "CWE-078",
  project_root: projectRoot,
  vulnerability_description: "Environment-controlled command reaches os.system.",
  patch_description: "The fixed variant removes the environment-controlled command.",
  vulnerable_database: { path: vulnerableDatabase, language: "python" },
  fixed_database: { path: fixedDatabase, language: "python" },
  validation: {
    vulnerable_min_results: 1,
    vulnerable_max_results: 1,
    fixed_min_results: 0,
    fixed_max_results: 0,
    must_have_code_flow: true,
    source: { label: "os.getenv", description: "environment source", file: "src/app.py", line: 5 },
    sink: { label: "os.system", description: "command sink", file: "src/app.py", line: 6 },
  },
  max_rounds: 3,
  timeout_ms: 300_000,
  created_at: "2026-08-26T00:00:00.000Z",
  input_provenance: "user_provided",
  reference_query_excluded: true,
  provenance: { fixture: "pi-m4-diagnostic", license: "MIT", source: "repository fixture" },
};

const faux = fauxProvider({
  provider: "autovul-m4-test",
  models: [{ id: "autovul-m4-test", reasoning: false, input: ["text"] }],
});

faux.setResponses([
  fauxAssistantMessage([fauxToolCall("codeql_database", { action: "inspect", path: vulnerableDatabase })], { stopReason: "toolUse" }),
  fauxAssistantMessage([fauxToolCall("codeql_database", { action: "inspect", path: fixedDatabase })], { stopReason: "toolUse" }),
  fauxAssistantMessage([fauxToolCall("codeql_workflow", { action: "start", spec })], { stopReason: "toolUse" }),
  (context) => fauxAssistantMessage([fauxToolCall("codeql_query", {
    action: "probe",
    run_id: workflowRunId(context),
    intent,
  })], { stopReason: "toolUse" }),
  (context) => fauxAssistantMessage([fauxToolCall("codeql_query", {
    action: "draft",
    run_id: workflowRunId(context),
    candidate: candidate(context),
  })], { stopReason: "toolUse" }),
  (context) => fauxAssistantMessage([fauxToolCall("codeql_query", {
    action: "verify",
    run_id: workflowRunId(context),
    candidate: candidate(context),
  })], { stopReason: "toolUse" }),
  (context) => fauxAssistantMessage([fauxToolCall("codeql_workflow", {
    action: "finalize",
    run_id: workflowRunId(context),
  })], { stopReason: "toolUse" }),
  fauxAssistantMessage([fauxText("M4 diagnostic Pi workflow complete")]),
]);

export default function autovulM4RpcProvider(pi) {
  pi.registerProvider(faux.provider);
}

function candidate(context) {
  const probe = toolResult(context, "codeql_query", (result) => typeof result?.probe_id === "string");
  return {
    schema_version: "v2.contracts/1",
    candidate_id: "pi-m4-candidate-1",
    query_id: "pi-m4-python-command-injection",
    spec_id: specId,
    language: "python",
    intent,
    probe_evidence: probe,
    round: 1,
    origin: "pi_generated",
    rationale: "Diagnostic Pi provider submits the probe-confirmed structured intent.",
  };
}

function workflowRunId(context) {
  const result = toolResult(context, "codeql_workflow");
  if (typeof result?.run?.runId !== "string") throw new Error("M4 Pi provider could not find workflow run id");
  return result.run.runId;
}

function toolResult(context, toolName, predicate = () => true) {
  for (const message of [...context.messages].reverse()) {
    if (message.role !== "toolResult" || message.toolName !== toolName) continue;
    for (const block of message.content ?? []) {
      if (block.type !== "text") continue;
      try {
        const envelope = JSON.parse(block.text);
        if (envelope.ok === true && predicate(envelope.result)) return envelope.result;
      } catch {
        // Continue looking for the structured result block.
      }
    }
  }
  throw new Error(`M4 Pi provider could not find ${toolName} result`);
}

function required(name) {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`${name} is required`);
  return value;
}
