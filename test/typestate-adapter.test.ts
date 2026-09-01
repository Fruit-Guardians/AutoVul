import { describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CodeqlTypestateAdapter } from "@autovul/codeql-runner";
import { type TypestateHypothesis } from "@autovul/contracts";
import { decideTypestate } from "@autovul/core";

import { processResult, ScriptedProcessPort } from "./helpers.js";

const scope = {
  kind: "single_file_named_function" as const,
  file: "fixture.js",
  entry: { kind: "named_function" as const, name: "login" },
  event_scope: "named_function_including_inline_callbacks" as const,
  alias_boundary: "direct_lexical_binding" as const,
};

const hypothesis: TypestateHypothesis = {
  schema_version: "autovul.typestate/1",
  hypothesis_id: "tstate-adapter-test",
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
  analysis_scope: scope,
};

const location = (line: number, endLine?: number) => ({ file: "fixture.js", start_line: line, ...(endLine === undefined ? {} : { end_line: endLine }) });

describe("CodeQL Typestate adapter", () => {
  it("normalizes real-shaped SARIF into identity-backed traces without deciding in the adapter", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-typestate-adapter-"));
    const process = new ScriptedProcessPort(async (command) => {
      if (command.args[0] === "version") return processResult({ stdout: "CodeQL command-line toolchain release 2.26.1.\n" });
      if (command.args[0] === "query") return processResult();
      const output = command.args.find((argument) => argument.startsWith("--output="))?.slice("--output=".length);
      if (output === undefined) return processResult({ exitCode: 2, stderr: "missing output" });
      const side = command.args[2]?.includes("fixed") ? "fixed" : "vulnerable";
      const query = command.args[3]?.includes("observations") ? "observations" : command.args[3]?.includes("violation") ? "violation" : "safe";
      const results = query === "observations"
        ? [
            sarifResult("TSTATE|kind=resource|resource=login_session", location(10)),
            sarifResult("TSTATE|kind=event|event=session_acquired", location(10)),
            ...(side === "fixed" ? [sarifResult("TSTATE|kind=event|event=regenerate_request_session", location(20, 22))] : []),
            sarifResult("TSTATE|kind=event|event=assign_user", location(side === "fixed" ? 30 : 12, side === "fixed" ? 32 : 15)),
          ]
        : query === "violation" && side === "vulnerable"
          ? [sarifResult("TSTATE|kind=trace|state=violating_witness|resource=login_session|events=session_acquired,assign_user|states=preauth,preauth;preauth,authenticated|", location(12, 15), [{ message: "event=session_acquired", location: location(10) }])]
          : query === "safe" && side === "fixed"
            ? [sarifResult("TSTATE|kind=trace|state=safe_trace|resource=login_session|events=session_acquired,regenerate_request_session,assign_user|states=preauth,preauth;preauth,rekeyed;rekeyed,authenticated|", location(30, 32), [{ message: "event=session_acquired", location: location(10) }, { message: "event=regenerate_request_session", location: location(20, 22) }])]
            : [];
      await mkdir(join(output, ".."), { recursive: true });
      await writeFile(output, JSON.stringify({ version: "2.1.0", runs: [{ results }] }), "utf8");
      return processResult();
    });
    try {
      const observation = await new CodeqlTypestateAdapter({ process }).execute({
        hypothesis,
        target: { vulnerable: { kind: "codeql_database", path: "/db/vulnerable" }, fixed: { kind: "codeql_database", path: "/db/fixed" } },
        analyzer_id: "codeql",
        mode: "differential",
        runId: "run_tstate_adapter",
        artifactRoot: root,
      }, { timeoutMs: 10_000 });
      expect(observation.compile_accepted).toBe(true);
      expect(observation.resource.state).toBe("observed");
      expect(observation.events.find((event) => event.event_id === "assign_user")?.state).toBe("observed");
      expect(observation.traces[0]).toMatchObject({ state: "violating_witness", violation_step: 1, evidence_ref: "typestate/tstate-adapter-test/vulnerable/violation.sarif" });
      expect(observation.fixed_traces?.[0]).toMatchObject({ state: "safe_trace", resource_id: "login_session" });
      expect(observation.fixed_traces?.[0]?.identity_evidence[0]?.kind).toBe("identity_change");
      expect(observation.fixed_traces?.[0]?.events.map((event) => event.event_id)).toEqual(["session_acquired", "regenerate_request_session", "assign_user"]);
      expect(observation.analyzer.evidence_kind).toBe("real_analyzer");
      expect(decideTypestate(observation, "differential", hypothesis).verificationLevel).toBe("differential");
      expect(process.calls.filter((call) => call.command.args[0] === "database")).toHaveLength(6);
      expect(await readFile(join(root, "typestate", hypothesis.hypothesis_id, "safe.ql"), "utf8")).toContain("req");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("returns a capability gap before invoking CodeQL for an unsupported identity plan", async () => {
    const process = new ScriptedProcessPort(() => processResult({ stdout: "must not run" }));
    const noIdentity = { ...hypothesis, transitions: [hypothesis.transitions[0], hypothesis.transitions[2]] } as TypestateHypothesis;
    const observation = await new CodeqlTypestateAdapter({ process }).execute({
      hypothesis: noIdentity,
      target: { vulnerable: { kind: "codeql_database", path: "/db/vulnerable" } },
      analyzer_id: "codeql",
      mode: "reproduce",
      runId: "run_tstate_gap",
      artifactRoot: "/unused",
    }, { timeoutMs: 10_000 });
    expect(observation.capability_gaps).toEqual([{ code: "TSTATE_IDENTITY_CHANGE_AMBIGUOUS", path: "/transitions" }]);
    expect(process.calls).toHaveLength(0);
  });

  it("downgrades a trace with missing related locations to inconclusive", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-typestate-incomplete-"));
    const process = new ScriptedProcessPort(async (command) => {
      if (command.args[0] === "version" || command.args[0] === "query") return processResult({ stdout: command.args[0] === "version" ? "CodeQL 2.26.1" : "" });
      const output = command.args.find((argument) => argument.startsWith("--output="))?.slice("--output=".length);
      if (output === undefined) return processResult({ exitCode: 2 });
      const query = command.args[3] ?? "";
      const results = query.includes("observations")
        ? [sarifResult("TSTATE|kind=resource|resource=login_session", location(10)), sarifResult("TSTATE|kind=event|event=session_acquired", location(10)), sarifResult("TSTATE|kind=event|event=assign_user", location(12, 15))]
        : query.includes("violation")
          ? [sarifResult("TSTATE|kind=trace|state=violating_witness|resource=login_session|events=session_acquired,assign_user|states=preauth,preauth;preauth,authenticated|", location(12, 15))]
          : [];
      await mkdir(join(output, ".."), { recursive: true });
      await writeFile(output, JSON.stringify({ version: "2.1.0", runs: [{ results }] }), "utf8");
      return processResult();
    });
    try {
      const observation = await new CodeqlTypestateAdapter({ process }).execute(requestFor("run_tstate_incomplete", root), { timeoutMs: 10_000 });
      expect(observation.traces[0]?.state).toBe("inconclusive");
      expect(decideTypestate(observation, "reproduce", hypothesis).decision.outcome).toBe("unknown");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("maps timeout, cancellation, and corrupt SARIF to stable analyzer errors", async () => {
    const timeout = new ScriptedProcessPort(() => processResult({ timedOut: true, exitCode: null }));
    await expect(new CodeqlTypestateAdapter({ process: timeout }).execute(requestFor("run_tstate_timeout"), { timeoutMs: 10 })).rejects.toMatchObject({ code: "PROCESS_TIMEOUT" });

    const cancelled = new ScriptedProcessPort(() => processResult({ cancelled: true, exitCode: null }));
    await expect(new CodeqlTypestateAdapter({ process: cancelled }).execute(requestFor("run_tstate_cancelled"), { timeoutMs: 10 })).rejects.toMatchObject({ code: "PROCESS_CANCELLED" });

    const root = await mkdtemp(join(tmpdir(), "autovul-typestate-corrupt-"));
    const corrupt = new ScriptedProcessPort(async (command) => {
      if (command.args[0] === "version" || command.args[0] === "query") return processResult({ stdout: command.args[0] === "version" ? "CodeQL 2.26.1" : "" });
      const output = command.args.find((argument) => argument.startsWith("--output="))?.slice("--output=".length);
      if (output !== undefined) {
        await mkdir(join(output, ".."), { recursive: true });
        await writeFile(output, "not SARIF", "utf8");
      }
      return processResult();
    });
    try {
      await expect(new CodeqlTypestateAdapter({ process: corrupt }).execute(requestFor("run_tstate_corrupt", root), { timeoutMs: 10_000 })).rejects.toMatchObject({ code: "ARTIFACT_CORRUPT" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

function requestFor(runId: string, artifactRoot = "/tmp/typestate-test-artifacts") {
  return { hypothesis, target: { vulnerable: { kind: "codeql_database" as const, path: "/db/vulnerable" } }, analyzer_id: "codeql" as const, mode: "reproduce" as const, runId, artifactRoot };
}

function sarifResult(message: string, primary: ReturnType<typeof location>, related: readonly { readonly message: string; readonly location: ReturnType<typeof location> }[] = []) {
  const encode = (item: ReturnType<typeof location>) => ({ physicalLocation: { artifactLocation: { uri: item.file }, region: { startLine: item.start_line, ...(item.end_line === undefined ? {} : { endLine: item.end_line }) } } });
  return { message: { text: message }, locations: [encode(primary)], relatedLocations: related.map((item, index) => ({ id: index + 1, message: { text: item.message }, ...encode(item.location) })) };
}
