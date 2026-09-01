import {
  fauxAssistantMessage,
  fauxProvider,
  fauxText,
  fauxToolCall,
} from "../node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/dist/index.js";

const vulnerable = required("AUTOVUL_PI_TYPESTATE_VULNERABLE_DB");
const fixed = required("AUTOVUL_PI_TYPESTATE_FIXED_DB");
const sourceFile = "ghost/core/core/server/services/auth/session/session-service.js";
const hypothesis = {
  schema_version: "autovul.typestate/1",
  hypothesis_id: "tstate-ghost-pi-real",
  language: "javascript",
  resource: { id: "login_session", kind: "local_binding", binding_name: "session", acquisition_event: "session_acquired", identity_model: "direct_lexical_binding" },
  initial_state: "preauth",
  states: ["preauth", "rekeyed", "authenticated"],
  events: [
    { id: "session_acquired", selector: { kind: "direct_call", name: "getSession" } },
    { id: "regenerate_request_session", selector: { kind: "direct_method", receiver: "req.session", name: "regenerate" } },
    { id: "assign_user", selector: { kind: "direct_call", name: "assignUserToSession", argument_property: "session" } },
  ],
  transitions: [
    { from_state: "preauth", event: "session_acquired", to_state: "preauth" },
    { from_state: "preauth", event: "regenerate_request_session", to_state: "rekeyed" },
    { from_state: "rekeyed", event: "assign_user", to_state: "authenticated" },
  ],
  violation: { kind: "prohibited_transition", from_state: "preauth", event: "assign_user", to_state: "authenticated", requires_same_identity: true },
  analysis_scope: {
    kind: "single_file_named_function",
    file: sourceFile,
    entry: { kind: "named_function", name: "createSessionForUser" },
    event_scope: "named_function_including_inline_callbacks",
    alias_boundary: "direct_lexical_binding",
  },
};

const faux = fauxProvider({
  provider: "autovul-typestate-test",
  models: [{ id: "autovul-typestate-test", reasoning: false, input: ["text"] }],
});

faux.setResponses([
  fauxAssistantMessage([fauxToolCall("autovul_research", { action: "validate", capability: "typestate", hypothesis_version: "autovul.typestate/1", hypothesis })], { stopReason: "toolUse" }),
  fauxAssistantMessage([fauxToolCall("autovul_research", {
    action: "execute",
    capability: "typestate",
    hypothesis_version: "autovul.typestate/1",
    hypothesis,
    target: { vulnerable: { kind: "codeql_database", path: vulnerable }, fixed: { kind: "codeql_database", path: fixed } },
    analyzer_id: "codeql",
    mode: "differential",
    budget: { timeout_ms: 300_000 },
    idempotency_key: "typestate-pi-real-golden",
  })], { stopReason: "toolUse" }),
  (context) => fauxAssistantMessage([fauxToolCall("autovul_run", { action: "replay", run_id: executedRunId(context) })], { stopReason: "toolUse" }),
  fauxAssistantMessage([fauxText("Typestate aggregate Pi acceptance complete")]),
]);

export default function typestatePiRpcProvider(pi) {
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
        // Continue looking for the structured execute result.
      }
    }
  }
  throw new Error("Typestate Pi provider could not find the executed run id");
}

function required(name) {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`${name} is required`);
  return value;
}
