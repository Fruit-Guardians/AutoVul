import { describe, expect, it } from "vitest";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import extension from "@pure-auto-codeql/pi-extension";

interface RegisteredCommand {
  readonly handler: (args: string, context: unknown) => Promise<void>;
}

interface RegisteredTool {
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
    const root = await mkdtemp(join(tmpdir(), "pure-auto-codeql-pi-"));
    const previousRunsDir = process.env.PURE_AUTO_CODEQL_V2_RUNS_DIR;
    const previousCodeqlPath = process.env.CODEQL_PATH;
    try {
      process.env.PURE_AUTO_CODEQL_V2_RUNS_DIR = root;
      process.env.CODEQL_PATH = await fakeCodeql(root);
      const pi = fakeExtensionApi();
      extension(pi);
      expect(pi.commands.has("codeql-doctor")).toBe(true);
      expect(pi.commands.has("codeql-status")).toBe(true);
      expect(pi.commands.has("codeql")).toBe(true);
      expect(pi.commands.has("codeql-generate")).toBe(true);
      expect(pi.tools.has("codeql_database")).toBe(true);
      expect(pi.tools.has("codeql_workflow")).toBe(true);
      expect(pi.tools.has("codeql_query")).toBe(true);
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
      expect(pi.widgets.get("pure-auto-codeql")).toBeUndefined();
      expect(pi.statuses.get("pure-auto-codeql")).toBe("CodeQL ready");

      const beforeAgentStart = pi.eventHandlers.get("before_agent_start") ?? [];
      const automaticGuidance = await beforeAgentStart[0]?.({
        type: "before_agent_start",
        prompt: "Analyze this Python CodeQL database for command injection and produce a Query Pack.",
        systemPrompt: "BASE SYSTEM",
      }, context);
      expect(automaticGuidance).toMatchObject({ systemPrompt: expect.any(String) });
      expect((automaticGuidance as { systemPrompt: string }).systemPrompt).toContain(
        "Use PureAutoCodeQL M4 inside the host Pi Agent Loop.",
      );
      expect((automaticGuidance as { systemPrompt: string }).systemPrompt).toContain("codeql_workflow");
      expect((automaticGuidance as { systemPrompt: string }).systemPrompt).toContain(
        "populate validation.source and validation.sink file/line before workflow start for every user-provided case",
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
        "Use PureAutoCodeQL M4 inside the host Pi Agent Loop.",
      );

      for (const handler of pi.eventHandlers.get("tool_execution_start") ?? []) {
        await handler({
          type: "tool_execution_start",
          toolName: "codeql_query",
          toolCallId: "tool-query",
          args: { candidate: { candidate_id: "candidate-1", round: 1, ql_text: "import python\nselect 1" } },
        }, context);
      }
      expect(pi.statuses.get("pure-auto-codeql")).toContain("CodeQL ◐ verify");
      const runningWidget = pi.widgets.get("pure-auto-codeql") ?? [];
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
      expect(pi.widgets.get("pure-auto-codeql")).toBeUndefined();
      expect(pi.statuses.get("pure-auto-codeql")).toContain("CodeQL ✓ differential");
      expect(pi.statuses.get("pure-auto-codeql")).toContain("vulnerable 1 flow");
      expect(pi.statuses.get("pure-auto-codeql")).toContain("fixed 0 flow");

      for (const handler of pi.eventHandlers.get("agent_settled") ?? []) {
        await handler({ type: "agent_settled" }, context);
      }
      expect(pi.widgets.get("pure-auto-codeql")).toBeUndefined();
      expect(pi.statuses.get("pure-auto-codeql")).toContain("CodeQL ✓ differential");

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
        delete process.env.PURE_AUTO_CODEQL_V2_RUNS_DIR;
      } else {
        process.env.PURE_AUTO_CODEQL_V2_RUNS_DIR = previousRunsDir;
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
