import { describe, expect, it } from "vitest";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import extension from "@autovul/pi-extension";

interface RegisteredCommand {
  readonly handler: (args: string, context: unknown) => Promise<void>;
}

interface RegisteredTool {
  readonly description: string;
  readonly promptSnippet: string;
  readonly execute: (...args: unknown[]) => Promise<unknown>;
}

interface FakePi {
  readonly commands: Map<string, RegisteredCommand>;
  readonly tools: Map<string, RegisteredTool>;
  readonly shutdownHandlers: Array<() => Promise<void>>;
  readonly eventHandlers: Map<string, Array<(event: unknown, context: unknown) => Promise<unknown> | unknown>>;
  readonly sentUserMessages: string[];
  readonly statuses: Map<string, string | undefined>;
  readonly widgets: Map<string, string[] | undefined>;
}

async function fakeCodeql(root: string): Promise<string> {
  const path = join(root, "fake-codeql");
  await writeFile(path, `#!/bin/sh
if [ "$1" = "version" ]; then echo "CodeQL CLI version 2.17.6"; else printf 'python\\n'; fi
`, "utf8");
  await chmod(path, 0o755);
  return path;
}

function fakeExtensionApi(): FakePi & ExtensionAPI {
  const fake: FakePi = {
    commands: new Map(),
    tools: new Map(),
    shutdownHandlers: [],
    eventHandlers: new Map(),
    sentUserMessages: [],
    statuses: new Map(),
    widgets: new Map(),
  };
  const api = {
    registerCommand: (name: string, options: RegisteredCommand): void => fake.commands.set(name, options),
    registerTool: (tool: { name: string }): void => fake.tools.set(tool.name, tool as unknown as RegisteredTool),
    sendUserMessage: (message: string): void => fake.sentUserMessages.push(message),
    on: (event: string, handler: (event: unknown, context: unknown) => Promise<unknown> | unknown): void => {
      if (event === "session_shutdown") {
        fake.shutdownHandlers.push(handler as () => Promise<void>);
        return;
      }
      const handlers = fake.eventHandlers.get(event) ?? [];
      handlers.push(handler);
      fake.eventHandlers.set(event, handlers);
    },
  };
  return Object.assign(fake, api) as unknown as FakePi & ExtensionAPI;
}

describe("Pi Extension", () => {
  it("registers thin commands/tool and routes tool calls to the shared Application API", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-pi-"));
    const previousRunsDir = process.env.AUTOVUL_RUNS_DIR;
    const previousCodeqlPath = process.env.CODEQL_PATH;
    try {
      process.env.AUTOVUL_RUNS_DIR = root;
      process.env.CODEQL_PATH = await fakeCodeql(root);
      const pi = fakeExtensionApi();
      extension(pi);
      expect(pi.commands.has("codeql-doctor")).toBe(true);
      expect(pi.commands.has("codeql-status")).toBe(true);
      expect(pi.commands.has("codeql")).toBe(true);
      expect(pi.commands.has("codeql-generate")).toBe(true);
      expect(pi.tools.has("autovul_research")).toBe(true);
      expect(pi.tools.has("autovul_run")).toBe(true);
      expect(pi.tools.has("codeql_database")).toBe(true);
      expect(pi.tools.has("codeql_workflow")).toBe(true);
      expect(pi.tools.has("codeql_query")).toBe(true);
      expect(pi.tools.get("autovul_research")?.description).toContain("Flow, MissingCheck, or Typestate");
      expect(pi.tools.get("autovul_research")?.description).toContain("Change Observation Analyzer");
      expect(pi.tools.get("autovul_research")?.promptSnippet).toContain("protected operation");
      expect(pi.tools.get("autovul_research")?.promptSnippet).toContain("change_observation");
      expect(pi.shutdownHandlers).toHaveLength(1);

      const notifications: string[] = [];
      const context = {
        hasUI: true,
        cwd: root,
        isIdle: () => true,
        ui: {
          notify: (message: string) => notifications.push(message),
          setStatus: (key: string, value: string | undefined) => pi.statuses.set(key, value),
          setWidget: (key: string, value: string[] | undefined) => pi.widgets.set(key, value),
          setWorkingMessage: () => undefined,
          editor: async () => undefined,
        },
      } as unknown as ExtensionCommandContext;

      for (const handler of pi.eventHandlers.get("session_start") ?? []) {
        await handler({ type: "session_start", reason: "startup" }, context);
      }
      expect(pi.widgets.get("autovul")).toBeUndefined();
      expect(pi.statuses.get("autovul")).toBe("CodeQL ready");

      const beforeAgentStart = pi.eventHandlers.get("before_agent_start") ?? [];
      const automaticGuidance = await beforeAgentStart[0]?.({
        type: "before_agent_start",
        prompt: "Analyze this Python CodeQL database for command injection and produce a Query Pack.",
        systemPrompt: "BASE SYSTEM",
      }, context);
      expect(automaticGuidance).toMatchObject({ systemPrompt: expect.any(String) });
      expect((automaticGuidance as { systemPrompt: string }).systemPrompt).toContain("autovul_research");
      expect((automaticGuidance as { systemPrompt: string }).systemPrompt).toContain("autovul_run");
      expect((automaticGuidance as { systemPrompt: string }).systemPrompt).toContain("not a third primary research interface");
      expect((automaticGuidance as { systemPrompt: string }).systemPrompt).toContain("source-to-sink value propagation");
      expect((automaticGuidance as { systemPrompt: string }).systemPrompt).toContain("protected operation is reachable");
      expect((automaticGuidance as { systemPrompt: string }).systemPrompt).toContain("do not encode a missing check as fake taint flow");
      expect((automaticGuidance as { systemPrompt: string }).systemPrompt).not.toContain(
        "Use AutoVul M4 inside the host Pi Agent Loop.",
      );

      const discoveryGuidance = await beforeAgentStart[0]?.({
        type: "before_agent_start",
        prompt: "Explain this TypeScript function.",
        systemPrompt: "BASE SYSTEM",
      }, context);
      expect(discoveryGuidance).toMatchObject({ systemPrompt: expect.any(String) });
      expect((discoveryGuidance as { systemPrompt: string }).systemPrompt).toContain(
        "Do not require the user to type /codeql-generate.",
      );
      expect((discoveryGuidance as { systemPrompt: string }).systemPrompt).not.toContain(
        "Use AutoVul M4 inside the host Pi Agent Loop.",
      );

      for (const handler of pi.eventHandlers.get("tool_execution_start") ?? []) {
        await handler({ type: "tool_execution_start", toolName: "autovul_research", toolCallId: "tool-validate", args: { action: "validate", capability: "missing_check" } }, context);
      }
      for (const handler of pi.eventHandlers.get("tool_result") ?? []) {
        await handler({ type: "tool_result", toolName: "autovul_research", toolCallId: "tool-validate", input: {}, content: [], isError: false, details: { valid: true, hypothesis: {}, issues: [], allowed_next_actions: ["execute", "stop"] } }, context);
      }
      expect(pi.statuses.get("autovul")).toContain("AutoVul ✓ missing_check · valid");
      expect(pi.statuses.get("autovul")).not.toContain("◐");
      expect(pi.widgets.get("autovul")?.join("\n")).toContain("missing_check · valid");

      for (const handler of pi.eventHandlers.get("tool_execution_start") ?? []) {
        await handler({
          type: "tool_execution_start",
          toolName: "autovul_research",
          toolCallId: "tool-missing-check",
          args: { action: "execute", hypothesis: { capability: "missing_check" } },
        }, context);
      }
      for (const handler of pi.eventHandlers.get("tool_result") ?? []) {
        await handler({
          type: "tool_result",
          toolName: "autovul_research",
          toolCallId: "tool-missing-check",
          input: {},
          content: [],
          isError: false,
          details: {
            schema_version: "v2.contracts/1",
            run_id: "run_mcheck",
            operation_status: "completed",
            capability: "missing_check",
            decision: { capability: "missing_check", outcome: "check_missing" },
            verification_level: "reproduced",
            observations: [{ code: "MCHECK_RELATION_UNCHECKED_WITNESS" }],
            revision_hints: [],
            allowed_next_actions: ["replay", "stop"],
            artifact_ref: "research/missing-check/result.json",
          },
        }, context);
      }
      expect(pi.statuses.get("autovul")).toContain("AutoVul ✓ missing_check · check_missing · reproduced");
      expect(pi.widgets.get("autovul")?.join("\n")).toContain("research/missing-check/result.json");

      for (const handler of pi.eventHandlers.get("tool_execution_start") ?? []) {
        await handler({
          type: "tool_execution_start",
          toolName: "autovul_research",
          toolCallId: "tool-typestate",
          args: { action: "execute", capability: "typestate" },
        }, context);
      }
      for (const handler of pi.eventHandlers.get("tool_result") ?? []) {
        await handler({
          type: "tool_result",
          toolName: "autovul_research",
          toolCallId: "tool-typestate",
          input: {},
          content: [],
          isError: false,
          details: {
            schema_version: "v2.contracts/1",
            run_id: "run_typestate",
            operation_status: "completed",
            capability: "typestate",
            decision: { capability: "typestate", outcome: "violation_observed" },
            verification_level: "reproduced",
            observations: [{ code: "TSTATE_TRACE_VIOLATING_WITNESS" }],
            revision_hints: [],
            allowed_next_actions: ["replay", "stop"],
            artifact_ref: "research/typestate/result.json",
          },
        }, context);
      }
      expect(pi.statuses.get("autovul")).toContain("AutoVul ✓ typestate · violation_observed · reproduced");
      expect(pi.widgets.get("autovul")?.join("\n")).toContain("research/typestate/result.json");

      for (const handler of pi.eventHandlers.get("tool_execution_start") ?? []) {
        await handler({
          type: "tool_execution_start",
          toolName: "codeql_query",
          toolCallId: "tool-query",
          args: { candidate: { candidate_id: "candidate-1", round: 1, ql_text: "import python\nselect 1" } },
        }, context);
      }
      expect(pi.statuses.get("autovul")).toContain("CodeQL ◐ verify");
      const runningWidget = pi.widgets.get("autovul") ?? [];
      expect(runningWidget).toHaveLength(1);
      expect(runningWidget.join("\n")).toContain("checking compile");
      expect(runningWidget.join("\n")).not.toContain("commands:");

      for (const handler of pi.eventHandlers.get("tool_result") ?? []) {
        await handler({
          type: "tool_result",
          toolName: "codeql_query",
          toolCallId: "tool-query",
          input: {},
          content: [],
          isError: false,
          details: {
            run_id: "run_test123",
            candidate_id: "candidate-1",
            round: 1,
            status: "passed",
            passed: true,
            verification_level: "differential",
            compile: { status: "passed" },
            vulnerable: { result_count: 1, code_flow_count: 1 },
            fixed: { result_count: 0, code_flow_count: 0 },
            diagnostics: [],
          },
        }, context);
      }
      expect(pi.widgets.get("autovul")).toBeUndefined();
      expect(pi.statuses.get("autovul")).toContain("CodeQL ✓ differential");
      expect(pi.statuses.get("autovul")).toContain("vulnerable 1 flow");
      expect(pi.statuses.get("autovul")).toContain("fixed 0 flow");

      for (const handler of pi.eventHandlers.get("agent_settled") ?? []) {
        await handler({ type: "agent_settled" }, context);
      }
      expect(pi.widgets.get("autovul")).toBeUndefined();
      expect(pi.statuses.get("autovul")).toContain("CodeQL ✓ differential");

      await pi.commands.get("codeql-generate")?.handler(
        "user input reaches subprocess.run(shell=True); vulnerable database /tmp/vuln",
        context,
      );
      expect(pi.sentUserMessages).toHaveLength(1);
      expect(pi.sentUserMessages[0]).toContain("Do not ask the user to write JSON");
      expect(pi.sentUserMessages[0]).toContain("/tmp/vuln");

      await pi.commands.get("codeql-doctor")?.handler("", context);
      expect(notifications.join("\n")).toContain("CodeQL ✓");
      await pi.commands.get("codeql-status")?.handler("", context);
      expect(notifications.join("\n")).not.toContain("Usage: /codeql-status");
      expect(notifications.join("\n")).toContain("CodeQL run");
      await pi.commands.get("codeql-status")?.handler("--json", context);
      expect(notifications.join("\n")).toContain('"ok": true');

      const toolResult = await pi.tools.get("codeql_database")?.execute(
        "tool-1",
        { action: "doctor" },
        undefined,
        undefined,
        context,
      );
      expect(JSON.stringify(toolResult)).toContain("CodeQL CLI version");
      await expect(pi.tools.get("codeql_database")?.execute(
        "tool-2",
        { action: "inspect" },
        undefined,
        undefined,
        context,
      )).rejects.toMatchObject({ code: "INVALID_INPUT", category: "input" });
      await pi.shutdownHandlers[0]?.();
    } finally {
      if (previousRunsDir === undefined) {
        delete process.env.AUTOVUL_RUNS_DIR;
      } else {
        process.env.AUTOVUL_RUNS_DIR = previousRunsDir;
      }
      if (previousCodeqlPath === undefined) {
        delete process.env.CODEQL_PATH;
      } else {
        process.env.CODEQL_PATH = previousCodeqlPath;
      }
      await rm(root, { recursive: true, force: true });
    }
  });
});
