import { describe, expect, it } from "vitest";

import {
  allLanguagePacks,
  languagePackFor,
  normalizeTaintIntent,
  qlpackForLanguage,
  renderTaintProbe,
  renderTaintQuery,
} from "@pure-auto-codeql/core";
import type { TaintQueryIntent } from "@pure-auto-codeql/contracts";

const intents: readonly TaintQueryIntent[] = [
  {
    schema_version: "v2.contracts/1",
    intent_id: "python-command-injection",
    language: "python",
    cwe: "CWE-078",
    query_kind: "path-problem",
    flow_mode: "taint",
    source: { kind: "call", module: "os", member: "getenv" },
    sink: { kind: "call", module: "os", member: "system", argument_index: 0 },
    message: "Environment-controlled command reaches os.system.",
  },
  {
    schema_version: "v2.contracts/1",
    intent_id: "javascript-command-injection",
    language: "javascript",
    cwe: "CWE-078",
    query_kind: "path-problem",
    flow_mode: "taint",
    source: { kind: "environment", name: "env.USER_COMMAND" },
    sink: { kind: "call", module: "child_process", member: "exec", argument_index: 0 },
    message: "Environment-controlled command reaches child_process.exec.",
  },
  {
    schema_version: "v2.contracts/1",
    intent_id: "java-path-traversal",
    language: "java",
    cwe: "CWE-022",
    query_kind: "path-problem",
    flow_mode: "taint",
    source: { kind: "call", type: "java.lang.System", member: "getenv" },
    sink: { kind: "constructor", type: "java.io.File", argument_index: 0 },
    message: "Environment-controlled path reaches java.io.File.",
  },
  {
    schema_version: "v2.contracts/1",
    intent_id: "cpp-buffer-overflow",
    language: "cpp",
    cwe: "CWE-120",
    query_kind: "path-problem",
    flow_mode: "taint",
    source: { kind: "function", name: "atoi" },
    sink: { kind: "array_index" },
    message: "Environment-controlled index reaches an array access.",
  },
];

describe("M3 Language Packs", () => {
  it("registers four independent packs with language-specific dependencies", () => {
    expect(allLanguagePacks().map((pack) => pack.language)).toEqual(["python", "javascript", "java", "cpp"]);
    expect(qlpackForLanguage("typescript")).toContain("codeql/javascript-all");
    expect(qlpackForLanguage("kotlin")).toContain("codeql/java-all");
    expect(qlpackForLanguage("c")).toContain("codeql/cpp-all");
  });

  it.each(intents)("renders a fixed path-query skeleton for $language", (intent) => {
    const ql = renderTaintQuery(`m3-${intent.language}`, intent);
    expect(ql).toContain("@kind path-problem");
    expect(ql).toContain(`@id pure-auto-codeql/m3-${intent.language}`);
    expect(ql).toContain("module Config implements DataFlow::ConfigSig");
    expect(ql).toContain("import Flow::PathGraph");
    expect(ql).toContain("where Flow::flowPath(source, sink)");
    expect(renderTaintProbe(intent)).toContain("@kind problem");
  });

  it("accepts a TypeScript intent through the JavaScript pack", () => {
    const intent = normalizeTaintIntent({
      ...intents[1],
      intent_id: "typescript-command-injection",
      language: "typescript",
    });
    expect(languagePackFor(intent.language).language).toBe("javascript");
    expect(renderTaintQuery("typescript-command-injection", intent)).toContain("import javascript");
  });

  it("maps a bare Python function name to the builtins module", () => {
    const intent = normalizeTaintIntent({
      ...intents[0],
      intent_id: "python-eval-builtin",
      source: { kind: "parameter", name: "value" },
      sink: { kind: "call", name: "eval", argument_index: 0 },
    });
    expect(renderTaintProbe(intent, "sink")).toContain('moduleImport("builtins").getMember("eval")');
  });

  it("rejects a matcher that the selected language pack cannot render", () => {
    expect(() => renderTaintQuery("bad-java", {
      ...intents[2],
      source: { kind: "array_index" },
    })).toThrow(/does not support|not implemented/);
  });
});
