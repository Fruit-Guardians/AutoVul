import { describe, expect, it } from "vitest";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CodeqlMissingCheckAdapter, CodeqlRunner, NodeFileSystemPort } from "@autovul/codeql-runner";
import { DomainError } from "@autovul/contracts";

import { processResult, ScriptedProcessPort } from "./helpers.js";

describe("CodeQL runner error mapping", () => {
  it("rejects MissingCheck version gaps and unreadable SARIF instead of returning complete not_run", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-mcheck-adapter-"));
    try {
      const versionFailure = new ScriptedProcessPort(() => processResult({ exitCode: 2, stderr: "version unavailable" }));
      const request = {
        hypothesis: {
          schema_version: "autovul.missing-check/1" as const,
          hypothesis_id: "mcheck-adapter-test",
          language: "javascript" as const,
          operation: { kind: "direct_call" as const, name: "dangerousOperation" },
          required_check: { kind: "direct_call" as const, name: "requiredCheck" },
          required_relation: "same_callback_cfg_dominates_operation" as const,
          scope: { kind: "single_file_named_entry_cfg" as const, file: "handler.ts", entry: { kind: "named_function" as const, name: "handler" } },
        },
        target: { vulnerable: { kind: "codeql_database" as const, path: "/db/vulnerable" } },
        analyzer_id: "codeql" as const,
        mode: "reproduce" as const,
        runId: "run_mcheck_adapter",
        artifactRoot: root,
      };
      await expect(new CodeqlMissingCheckAdapter({ process: versionFailure, filesystem: new NodeFileSystemPort() }).execute(request, { timeoutMs: 1_000 })).rejects.toMatchObject({ code: "CODEQL_RESOLVE_FAILED" });
      expect(versionFailure.calls).toHaveLength(1);

      const invalidSarif = new ScriptedProcessPort(async (command) => {
        if (command.args[0] === "version") return processResult({ stdout: "CodeQL CLI version 2.26.1\n" });
        const output = command.args.find((argument) => argument.startsWith("--output="))?.slice("--output=".length);
        if (output !== undefined) {
          await mkdir(join(output, ".."), { recursive: true });
          await writeFile(output, "not valid SARIF", "utf8");
        }
        return processResult();
      });
      await expect(new CodeqlMissingCheckAdapter({ process: invalidSarif, filesystem: new NodeFileSystemPort() }).execute(request, { timeoutMs: 1_000 })).rejects.toMatchObject({ code: "ARTIFACT_CORRUPT", details: { side: "vulnerable", kind: "operations" } });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("discovers the CLI and extractor list with argument arrays and shell false", async () => {
    const process = new ScriptedProcessPort((command) => {
      expect(command.shell).toBe(false);
      expect(Array.isArray(command.args)).toBe(true);
      if (command.args[0] === "version") {
        return processResult({ stdout: "CodeQL CLI version 2.17.6\n" });
      }
      return processResult({ stdout: "cpp (/opt/codeql/cpp)\npython (/opt/codeql/python)\n" });
    });
    const result = await new CodeqlRunner({ process, executable: "/opt/codeql" }).doctor({ timeoutMs: 1000 });
    expect(result.languages).toEqual(["cpp", "python"]);
    expect(result.cliPath).toBe("/opt/codeql");
    expect(process.calls).toHaveLength(2);
  });

  it.each([
    ["timeout", processResult({ timedOut: true, exitCode: null }), "PROCESS_TIMEOUT"],
    ["cancel", processResult({ cancelled: true, exitCode: null }), "PROCESS_CANCELLED"],
    ["exit", processResult({ exitCode: 17, stderr: "failed" }), "PROCESS_EXITED"],
  ] as const)("maps %s to a stable error", async (_name, result, code) => {
    const process = new ScriptedProcessPort(() => result);
    await expect(new CodeqlRunner({ process }).doctor({ timeoutMs: 20 })).rejects.toMatchObject({ code });
  });

  it("maps a missing executable and missing extractors", async () => {
    const missing = new ScriptedProcessPort(() => {
      throw new Error("spawn codeql ENOENT");
    });
    await expect(new CodeqlRunner({ process: missing }).doctor({ timeoutMs: 20 })).rejects.toMatchObject({
      code: "CODEQL_CLI_NOT_FOUND",
    });

    const noExtractor = new ScriptedProcessPort((command) =>
      command.args[0] === "version" ? processResult({ stdout: "2.0" }) : processResult({ stdout: "\n" }),
    );
    await expect(new CodeqlRunner({ process: noExtractor }).doctor({ timeoutMs: 20 })).rejects.toMatchObject({
      code: "CODEQL_EXTRACTOR_MISSING",
    });
  });

  it("inspects a directory read-only and rejects invalid databases without leaking secrets", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-runner-"));
    const database = join(root, "database");
    await mkdir(database);
    try {
      const process = new ScriptedProcessPort(() => processResult({
        stdout: JSON.stringify({ language: "python", codeqlVersion: "2.17.6" }),
      }));
      const manifest = await new CodeqlRunner({ process, filesystem: new NodeFileSystemPort() }).inspectDatabase(database, {
        timeoutMs: 1000,
      });
      expect(manifest.valid).toBe(true);
      expect(manifest.language).toBe("python");
      expect(process.calls.at(-1)?.command.args.slice(0, 4)).toEqual(["resolve", "database", "--format=json", "--"]);
      expect(process.calls.at(-1)?.command.args[4]).toBe(manifest.canonicalPath);

      const bounded = new CodeqlRunner({
        process,
        filesystem: new NodeFileSystemPort(),
        workspaceRoot: root,
      });
      expect((await bounded.inspectDatabase(database, { timeoutMs: 1000 })).valid).toBe(true);
      const outsideRoot = await mkdtemp(join(tmpdir(), "autovul-runner-outside-"));
      try {
        await expect(bounded.inspectDatabase(outsideRoot, { timeoutMs: 1000 })).rejects.toMatchObject({
          code: "DATABASE_PATH_OUTSIDE_WORKSPACE",
        });
      } finally {
        await rm(outsideRoot, { recursive: true, force: true });
      }

      const workflowBound = new CodeqlRunner({
        process,
        filesystem: new NodeFileSystemPort(),
      });
      workflowBound.setTrustedRoots?.([database]);
      expect((await workflowBound.inspectDatabase(database, { timeoutMs: 1000 })).valid).toBe(true);

      const staticBound = new CodeqlRunner({
        process,
        filesystem: new NodeFileSystemPort(),
        workspaceRoot: root,
      });
      staticBound.setTrustedRoots?.(["/tmp"]);
      expect((await staticBound.inspectDatabase(database, { timeoutMs: 1000 })).valid).toBe(true);

      const invalid = new ScriptedProcessPort(() => processResult({ exitCode: 2, stderr: "password=top-secret" }));
      const error = await new CodeqlRunner({ process: invalid }).inspectDatabase(database, { timeoutMs: 1000 }).catch((value: unknown) => value);
      expect(error).toBeInstanceOf(DomainError);
      expect(error).toMatchObject({ code: "DATABASE_INVALID" });
      expect(JSON.stringify(error)).not.toContain("top-secret");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects a directory when CodeQL cannot resolve formal database metadata", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-runner-metadata-"));
    const database = join(root, "database");
    await mkdir(database);
    try {
      const process = new ScriptedProcessPort(() => processResult({ stdout: "null\n" }));
      await expect(new CodeqlRunner({ process, filesystem: new NodeFileSystemPort() }).inspectDatabase(database, {
        timeoutMs: 1000,
      })).rejects.toMatchObject({ code: "DATABASE_INVALID" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("reads the languages array emitted by a finalized CodeQL database", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-runner-languages-"));
    const database = join(root, "database");
    await mkdir(database);
    try {
      const process = new ScriptedProcessPort(() => processResult({ stdout: JSON.stringify({ languages: ["javascript"] }) }));
      const manifest = await new CodeqlRunner({ process, filesystem: new NodeFileSystemPort() }).inspectDatabase(database, {
        timeoutMs: 1000,
      });
      expect(manifest.language).toBe("javascript");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("keeps finalized database fingerprints stable across relocation and query-side directory changes", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-runner-fingerprint-"));
    const first = join(root, "first");
    const relocated = join(root, "relocated");
    await mkdir(first);
    await mkdir(relocated);
    const identity = "primaryLanguage: javascript\nbaselineLinesOfCode: 42\ncreationMetadata:\n  cliVersion: 2.26.1\n  creationTime: 2026-08-31T00:00:00Z\nbuildMode: none\n";
    await writeFile(join(first, "codeql-database.yml"), identity, "utf8");
    await writeFile(join(relocated, "codeql-database.yml"), identity, "utf8");
    try {
      const process = new ScriptedProcessPort(() => processResult({ stdout: JSON.stringify({ languages: ["javascript"] }) }));
      const runner = new CodeqlRunner({ process, filesystem: new NodeFileSystemPort() });
      const firstFingerprint = (await runner.inspectDatabase(first, { timeoutMs: 1_000 })).portableFingerprint;
      await writeFile(join(first, "query-cache-marker"), "changed after analysis", "utf8");
      expect((await runner.inspectDatabase(first, { timeoutMs: 1_000 })).portableFingerprint).toBe(firstFingerprint);
      expect((await runner.inspectDatabase(relocated, { timeoutMs: 1_000 })).portableFingerprint).toBe(firstFingerprint);
      await writeFile(join(relocated, "codeql-database.yml"), identity.replace("2026-08-31T00:00:00Z", "2026-08-31T00:00:01Z"), "utf8");
      expect((await runner.inspectDatabase(relocated, { timeoutMs: 1_000 })).portableFingerprint).not.toBe(firstFingerprint);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it.each([
    [JSON.stringify("python"), "python"],
    [JSON.stringify({ primaryLanguage: "python" }), "python"],
    [JSON.stringify({ languages: ["python", "javascript"] }), "python"],
  ])("accepts resolve database metadata shape %s", async (output, language) => {
    const root = await mkdtemp(join(tmpdir(), "autovul-runner-metadata-shape-"));
    const database = join(root, "database");
    await mkdir(database);
    try {
      const process = new ScriptedProcessPort(() => processResult({ stdout: output }));
      const result = await new CodeqlRunner({ process, filesystem: new NodeFileSystemPort() }).inspectDatabase(database, {
        timeoutMs: 1000,
      });
      expect(result.language).toBe(language);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
