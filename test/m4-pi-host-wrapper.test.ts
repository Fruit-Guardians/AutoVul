import { describe, expect, it } from "vitest";

import { buildPiArgs, parsePiJsonOutput } from "./m4-pi-host-wrapper.mjs";

describe("M4 Pi host wrapper output adapter", () => {
  it("extracts structured assistant JSON and provider usage from Pi JSONL", () => {
    const output = [
      JSON.stringify({
        type: "message_end",
        message: {
          role: "assistant",
          provider: "openai-codex",
          model: "host-model",
          content: [{ type: "text", text: "```json\n{\"candidate\":{\"intent\":{}}}\n```" }],
        },
      }),
      JSON.stringify({
        type: "turn_end",
        message: { role: "assistant", usage: { input: 12, output: 8, totalTokens: 20 } },
      }),
    ].join("\n");

    expect(parsePiJsonOutput(output)).toEqual({
      value: { candidate: { intent: {} } },
      provider: "openai-codex",
      model: "host-model",
      usage: { input: 12, output: 8, totalTokens: 20 },
    });
  });

  it("rejects a Pi turn without structured JSON content", () => {
    expect(() => parsePiJsonOutput(JSON.stringify({ type: "agent_end", messages: [] }))).toThrow("PI_GENERATOR_JSON_MISSING");
  });

  it("keeps provider extensions enabled while disabling model tools", () => {
    const args = buildPiArgs(
      { candidateInput: { workflow_id: "wf-1" } },
      {
        PURE_AUTO_CODEQL_M4_PI_PROVIDER: "commandcode",
        PURE_AUTO_CODEQL_M4_PI_MODEL: "gpt-5.6-luna",
        PURE_AUTO_CODEQL_M4_PI_THINKING: "low",
      },
    );

    expect(args).toContain("--no-tools");
    expect(args).not.toContain("--no-extensions");
    expect(args).toEqual(expect.arrayContaining(["--system-prompt", expect.stringContaining("RFC 8259 JSON")]))
    expect(args).toEqual(expect.arrayContaining(["--provider", "commandcode", "--model", "gpt-5.6-luna"]));
    expect(args.at(-1)).toContain('"workflow_id":"wf-1"');
    expect(args.at(-1)).toContain("schema_version, intent_id, language, cwe, query_kind, flow_mode, source, sink, message");
    expect(args.at(-1)).toContain("Each source/sink matcher must contain");
  });

  it("can isolate a built-in provider from unrelated piagent extensions", () => {
    const args = buildPiArgs(
      { workflow_id: "wf-2" },
      { PURE_AUTO_CODEQL_M4_PI_NO_EXTENSIONS: "true" },
    );

    expect(args).toContain("--no-extensions");
  });

  it("gives JavaScript property-chain and member-call matchers an exact shape", () => {
    const args = buildPiArgs(
      { language: "javascript", source_context: { files: [] } },
      {},
    );

    expect(args.at(-1)).toContain('process.env.NAME');
    expect(args.at(-1)).toContain('"module":"process"');
    expect(args.at(-1)).toContain('"property":"env.NAME"');
    expect(args.at(-1)).toContain('"module":"child_process"');
    expect(args.at(-1)).toContain('"member":"exec"');
  });
});
