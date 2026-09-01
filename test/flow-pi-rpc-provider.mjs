import {
  fauxAssistantMessage,
  fauxProvider,
  fauxText,
  fauxToolCall,
} from "../node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/dist/index.js";

const vulnerable = required("AUTOVUL_PI_FLOW_VULNERABLE_DB");
const fixed = required("AUTOVUL_PI_FLOW_FIXED_DB");
const model = {
  schema_version: "autovul.flow/1",
  model_id: "pi-flow-python-command-injection",
  language: "python",
  flow_mode: "taint",
  source: { kind: "environment", name: "getenv" },
  sink: { kind: "call", module: "os", member: "system", argument_index: 0 },
};
const validate = {
  action: "validate",
  capability: "flow",
  hypothesis_version: "autovul.flow/1",
  hypothesis: model,
};
const execute = {
  action: "execute",
  capability: "flow",
  hypothesis_version: "autovul.flow/1",
  hypothesis: model,
  analyzer_id: "codeql",
  mode: "differential",
  target: {
    vulnerable: { kind: "codeql_database", path: vulnerable },
    fixed: { kind: "codeql_database", path: fixed },
  },
  expectation: { vulnerable: { min_paths: 1, max_paths: 1 }, fixed: { min_paths: 0, max_paths: 0 } },
  budget: { timeout_ms: 300_000 },
  idempotency_key: "pi-flow-python-command-injection",
};

const faux = fauxProvider({
  provider: "autovul-flow-test",
  models: [{ id: "autovul-flow-test", reasoning: false, input: ["text"] }],
});

faux.setResponses([
  fauxAssistantMessage([fauxToolCall("autovul_research", validate)], { stopReason: "toolUse" }),
  fauxAssistantMessage([fauxToolCall("autovul_research", execute)], { stopReason: "toolUse" }),
  (context) => fauxAssistantMessage([fauxToolCall("autovul_run", { action: "replay", run_id: executedRunId(context) })], { stopReason: "toolUse" }),
  fauxAssistantMessage([fauxText("Flow aggregate Pi RPC acceptance complete")]),
]);

export default function flowPiRpcProvider(pi) {
  pi.registerProvider(faux.provider);
}

function executedRunId(context) {
  for (const message of [...context.messages].reverse()) {
    if (message.role !== "toolResult" || message.toolName !== "autovul_research") continue;
    for (const block of message.content ?? []) {
      if (block.type !== "text") continue;
      try {
        const envelope = JSON.parse(block.text);
        if (envelope.ok === true && envelope.result?.operation_status === "completed" && typeof envelope.result.run_id === "string") return envelope.result.run_id;
      } catch {
        // Continue looking for the execute result.
      }
    }
  }
  throw new Error("Flow Pi provider could not find the executed run id");
}

function required(name) {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`${name} is required`);
  return value;
}
