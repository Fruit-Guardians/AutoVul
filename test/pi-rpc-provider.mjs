import {
  fauxAssistantMessage,
  fauxProvider,
  fauxText,
  fauxToolCall,
} from "../node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/dist/index.js";

const scenario = process.env.PURE_AUTO_CODEQL_PI_SCENARIO ?? "success";
const faux = fauxProvider({
  provider: "pure-auto-codeql-test",
  models: [{ id: "pure-auto-codeql-test", reasoning: false, input: ["text"] }],
});

const toolInput = scenario === "error"
  ? { action: "inspect", path: `${process.cwd()}/missing-codeql-database` }
  : { action: "doctor" };

if (scenario === "m2" || scenario === "m2-cancel-start") {
  const dbRoot = process.env.PURE_AUTO_CODEQL_PI_M2_DB_ROOT ?? `${process.cwd()}/test/.pi-m2-db`;
  const spec = {
    schema_version: "v2.contracts/1",
    spec_id: "pi-python-command-injection",
    language: "python",
    cwe: "CWE-078",
    vulnerability_description: "environment input reaches os.system",
    vulnerable_database: { path: `${dbRoot}/vulnerable`, language: "python" },
    fixed_database: { path: `${dbRoot}/fixed`, language: "python" },
    validation: { vulnerable_min_results: 1, vulnerable_max_results: 1, fixed_min_results: 0, fixed_max_results: 0, must_have_code_flow: true },
    max_rounds: 3,
    timeout_ms: 30_000,
    created_at: "2026-08-24T00:00:00.000Z",
    input_provenance: "golden_fixture",
    reference_query_excluded: true,
    provenance: { fixture: "fake-pi", license: "test", source: "fake-pi" },
  };
  const candidate = {
    schema_version: "v2.contracts/1",
    candidate_id: "pi-candidate-1",
    query_id: "pi-query-1",
    spec_id: spec.spec_id,
    language: "python",
    draft: {
      schema_version: "v2.contracts/1",
      source_predicate: "true",
      sink_predicate: "true",
      message: "fake Python flow",
    },
    round: 1,
    origin: "pi_generated",
  };
  faux.setResponses(scenario === "m2-cancel-start"
    ? [
        fauxAssistantMessage([fauxToolCall("codeql_workflow", { action: "start", spec })], { stopReason: "toolUse" }),
        fauxAssistantMessage([fauxText("scenario m2 start cancellation complete")]),
      ]
    : [
        fauxAssistantMessage([fauxToolCall("codeql_workflow", { action: "start", spec })], { stopReason: "toolUse" }),
        (context) => fauxAssistantMessage([fauxToolCall("codeql_query", { action: "verify", run_id: workflowRunId(context), candidate })], { stopReason: "toolUse" }),
        (context) => fauxAssistantMessage([fauxToolCall("codeql_workflow", { action: "finalize", run_id: workflowRunId(context) })], { stopReason: "toolUse" }),
        fauxAssistantMessage([fauxText("scenario m2 complete")]),
      ]);
} else {
  faux.setResponses([
    fauxAssistantMessage([fauxToolCall("codeql_database", toolInput)], { stopReason: "toolUse" }),
    fauxAssistantMessage([fauxText(`scenario ${scenario} complete`)]),
  ]);
}

function workflowRunId(context) {
  for (const message of [...context.messages].reverse()) {
    if (message.role !== "toolResult" || message.toolName !== "codeql_workflow") continue;
    for (const block of message.content) {
      if (block.type !== "text") continue;
      try {
        const envelope = JSON.parse(block.text);
        if (envelope.ok === true && envelope.result?.run?.runId) return envelope.result.run.runId;
      } catch {
        // Continue looking for the structured tool result block.
      }
    }
  }
  throw new Error("M2 faux provider could not find workflow run id");
}

export default function pureAutoCodeqlRpcProvider(pi) {
  pi.registerProvider(faux.provider);
  pi.on("session_start", async (event, ctx) => {
    if (event.reason === "reload") {
      ctx.ui.notify("pi-e2e-reload-complete", "info");
    }
  });
  pi.registerCommand("pi-e2e-reload", {
    description: "Reload the Pi extension runtime for the RPC test",
    handler: async (_args, ctx) => {
      await ctx.reload();
    },
  });
}
