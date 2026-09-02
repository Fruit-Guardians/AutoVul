import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { DomainError } from "@autovul/contracts";
import { normalizeChangeObservation, resolveChangeObservationInput, toChangeObservationPortRequest } from "@autovul/core";
import { GitChangeObservationAdapter } from "@autovul/codeql-runner";

import { processResult, ScriptedProcessPort } from "./helpers.js";

const baseOid = "75b4c059b8405dfbd50884b773346a9946fabd20";
const headOid = "80b1fa17bfc3f6a668492f0326ea52f48bb89776";
const baseTree = "0123456789abcdef0123456789abcdef01234567";
const headTree = "89abcdef0123456789abcdef0123456789abcdef";
const execFile = promisify(execFileCallback);

function request() {
  return toChangeObservationPortRequest(resolveChangeObservationInput({
    repository: { kind: "trusted_local_git_repository", path: "/trusted/repository" },
    base_revision: baseOid,
    head_revision: headOid,
    budget: { max_hunk_lines: 8 },
  }));
}

function scriptedGit(options: { readonly missingHead?: boolean; readonly statusOutput?: string; readonly binaryPaths?: readonly string[] } = {}) {
  return new ScriptedProcessPort((command) => {
    const args = command.args;
    if (args.includes("--version")) return processResult({ stdout: "git version 2.47.0\n" });
    if (args.includes("--git-dir")) return processResult({ stdout: ".git\n" });
    if (args.includes("--show-object-format")) return processResult({ stdout: "sha1\n" });
    if (args.includes("--is-shallow-repository")) return processResult({ stdout: "false\n" });
    if (args.includes("cat-file")) {
      if (options.missingHead && args.at(-1) === headOid) return processResult({ exitCode: 1, stderr: "missing" });
      return processResult({ stdout: "commit\n" });
    }
    if (args.includes("rev-parse")) {
      return processResult({ stdout: args.at(-1) === `${baseOid}^{tree}` ? `${baseTree}\n` : `${headTree}\n` });
    }
    if (args.includes("ls-tree")) return processResult({ stdout: `100644 blob ${baseTree}\tsrc/session.ts\0` });
    if (args.includes("--name-status")) return processResult({ stdout: options.statusOutput ?? "M\0src/session.ts\0" });
    if (args.includes("--numstat")) {
      const path = args.at(-1);
      return processResult({ stdout: options.binaryPaths?.includes(path ?? "") ? `-\t-\t${path}\n` : `2\t1\t${path}\n` });
    }
    if (args.includes("--unified=0")) {
      return processResult({ stdout: [
        "diff --git a/src/session.ts b/src/session.ts",
        "@@ -2 +2,2 @@",
        "-  req.session.save(user);",
        "+  req.session.regenerate(() => {});",
        "+  req.session.save(user, true);",
        "",
      ].join("\n") });
    }
    if (args.includes("show")) {
      return processResult({ stdout: args.at(-1)?.startsWith(`${baseOid}:`)
        ? "function assign(user) {\n  req.session.save(user);\n}\n"
        : "function assign(user) {\n  req.session.regenerate(() => {});\n  req.session.save(user, true);\n}\n" });
    }
    throw new Error(`Unexpected Git invocation: ${args.join(" ")}`);
  });
}

describe("GitChangeObservationAdapter", () => {
  it("uses the fixed read-only object profile and returns bounded structural facts", async () => {
    const process = scriptedGit();
    const adapter = new GitChangeObservationAdapter({
      trustedRoots: ["/trusted"],
      process,
      filesystem: { canonicalize: async (path) => path },
    });

    const raw = await adapter.observe(request(), {});
    const observation = normalizeChangeObservation(resolveChangeObservationInput(request().input), raw);

    expect(observation.completeness).toBe("complete");
    expect(observation.changed_files).toEqual([{ path: "src/session.ts", change_kind: "modified", content_kind: "text" }]);
    expect(observation.normalized_hunks).toMatchObject([{
      path: "src/session.ts",
      ordinal: 0,
      old_start: 2,
      old_line_count: 1,
      new_start: 2,
      new_line_count: 2,
      removed_line_count: 1,
      added_line_count: 2,
      truncated: false,
    }]);
    expect(observation.symbols).toEqual(expect.arrayContaining([
      expect.objectContaining({ change_kind: "modified", symbol_kind: "function", name: "assign", language: "typescript" }),
    ]));
    expect(observation.call_changes).toEqual(expect.arrayContaining([
      expect.objectContaining({ change_kind: "added", callee_selector: ["req", "session", "regenerate"], new_argument_count: 1 }),
      expect.objectContaining({ change_kind: "modified", callee_selector: ["req", "session", "save"], argument_change_kind: "count_changed", old_argument_count: 1, new_argument_count: 2 }),
    ]));
    expect(observation.event_changes).toEqual(expect.arrayContaining([
      expect.objectContaining({ event_kind: "direct_call_added", selector: ["req", "session", "regenerate"] }),
      expect.objectContaining({ event_kind: "direct_call_modified", selector: ["req", "session", "save"] }),
    ]));
    expect(observation.provenance).toMatchObject({
      git_version: "git version 2.47.0",
      command_profile_version: "autovul.git-change-observation/1",
      parser_versions: [{ language: "typescript", version: "5.9.3" }],
    });
    expect(process.calls).not.toEqual([]);
    expect(process.calls.every(({ command }) => command.shell === false && command.cwd === "/trusted/repository")).toBe(true);
    expect(process.calls.every(({ command }) => command.env?.GIT_CONFIG_NOSYSTEM === "1" && command.env?.GIT_TERMINAL_PROMPT === "0")).toBe(true);
    const rendered = process.calls.map(({ command }) => command.args.join(" ")).join("\n");
    expect(rendered).toContain("--no-ext-diff");
    expect(rendered).toContain("--no-textconv");
    expect(rendered).not.toMatch(/\b(checkout|reset|clean|switch|merge|rebase|fetch|pull|clone|submodule|install|test)\b/);
    expect(process.calls.filter(({ command }) => command.args.includes("show") || command.args.includes("--unified=0")).every(({ options }) => options.redactOutput === false)).toBe(true);
    expect(process.calls.filter(({ command }) => !command.args.includes("show") && !command.args.includes("--unified=0")).every(({ options }) => options.redactOutput !== false)).toBe(true);
  });

  it("rejects an out-of-root repository before starting Git", async () => {
    const process = scriptedGit();
    const adapter = new GitChangeObservationAdapter({
      trustedRoots: ["/trusted/other"],
      process,
      filesystem: { canonicalize: async (path) => path },
    });

    await expect(adapter.observe(request(), {})).rejects.toMatchObject<Partial<DomainError>>({
      code: "CHANGE_OBSERVATION_REPOSITORY_UNTRUSTED",
    });
    expect(process.calls).toHaveLength(0);
  });

  it("reports a missing immutable revision as a structured adapter error", async () => {
    const adapter = new GitChangeObservationAdapter({
      trustedRoots: ["/trusted"],
      process: scriptedGit({ missingHead: true }),
      filesystem: { canonicalize: async (path) => path },
    });

    await expect(adapter.observe(request(), {})).rejects.toMatchObject<Partial<DomainError>>({
      code: "REVISION_OBJECT_MISSING",
      details: { revision: "head" },
    });
  });

  it("preserves caller cancellation through the read-only process boundary", async () => {
    const adapter = new GitChangeObservationAdapter({
      trustedRoots: ["/trusted"],
      process: new ScriptedProcessPort(() => processResult({ cancelled: true })),
      filesystem: { canonicalize: async (path) => path },
    });

    await expect(adapter.observe(request(), {})).rejects.toMatchObject<Partial<DomainError>>({
      code: "PROCESS_CANCELLED",
      details: { stage: "repository" },
    });
  });

  it("keeps rename, binary, and unavailable-parser facts structural and partial", async () => {
    const adapter = new GitChangeObservationAdapter({
      trustedRoots: ["/trusted"],
      process: scriptedGit({
        statusOutput: "R100\0src/old.ts\0src/new.ts\0M\0assets/logo.bin\0A\0scripts/check.py\0",
        binaryPaths: ["assets/logo.bin"],
      }),
      filesystem: { canonicalize: async (path) => path },
    });

    const raw = await adapter.observe(request(), {});
    const observation = normalizeChangeObservation(resolveChangeObservationInput(request().input), raw);

    expect(observation.completeness).toBe("partial");
    expect(observation.changed_files).toEqual(expect.arrayContaining([
      { path: "src/new.ts", previous_path: "src/old.ts", change_kind: "renamed", content_kind: "text" },
      { path: "assets/logo.bin", change_kind: "modified", content_kind: "binary" },
      { path: "scripts/check.py", change_kind: "added", content_kind: "text" },
    ]));
    expect(observation.analysis_gaps).toEqual(expect.arrayContaining([
      { code: "BINARY_FILE_SKIPPED", path: "assets/logo.bin" },
      { code: "PARSER_UNAVAILABLE", path: "scripts/check.py", parser_or_language: "py" },
    ]));
    expect(JSON.stringify(observation)).not.toContain("req.session.save(user)");
  });

  it("reads only committed objects with the real Git and process adapters", async () => {
    const repository = await mkdtemp(join(tmpdir(), "autovul-change-observation-"));
    try {
      await git(repository, ["init", "--initial-branch=main"]);
      await git(repository, ["config", "user.email", "adapter-test@example.invalid"]);
      await git(repository, ["config", "user.name", "Adapter Test"]);
      await mkdir(join(repository, "src"), { recursive: true });
      await writeFile(join(repository, "src", "session.ts"), "export function assign(user: string) {\n  session.save(user);\n}\n", "utf8");
      await git(repository, ["add", "src/session.ts"]);
      await git(repository, ["commit", "-m", "base"]);
      const base = await gitOutput(repository, ["rev-parse", "HEAD"]);

      await writeFile(join(repository, "src", "session.ts"), "export function assign(user: string) {\n  session.regenerate();\n  session.save(user, true);\n}\n", "utf8");
      await git(repository, ["add", "src/session.ts"]);
      await git(repository, ["commit", "-m", "head"]);
      const head = await gitOutput(repository, ["rev-parse", "HEAD"]);
      await writeFile(join(repository, "worktree-only.ts"), "session.destroy();\n", "utf8");

      const adapter = new GitChangeObservationAdapter({ trustedRoots: [repository] });
      const resolved = resolveChangeObservationInput({
        repository: { kind: "trusted_local_git_repository", path: repository },
        base_revision: base,
        head_revision: head,
      });
      const observation = normalizeChangeObservation(resolved, await adapter.observe(toChangeObservationPortRequest(resolved), {}));

      expect(observation.changed_files).toEqual([{ path: "src/session.ts", change_kind: "modified", content_kind: "text" }]);
      expect(observation.call_changes).toEqual(expect.arrayContaining([
        expect.objectContaining({ change_kind: "added", callee_selector: ["session", "regenerate"] }),
        expect.objectContaining({ change_kind: "modified", callee_selector: ["session", "save"] }),
      ]));
      expect(observation.changed_files.some((file) => file.path === "worktree-only.ts")).toBe(false);
      expect(observation.event_changes.some((event) => event.selector.join(".") === "session.destroy")).toBe(false);
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });
});

async function git(repository: string, args: readonly string[]): Promise<void> {
  await execFile("git", [...args], { cwd: repository, env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" } });
}

async function gitOutput(repository: string, args: readonly string[]): Promise<string> {
  const result = await execFile("git", [...args], { cwd: repository, env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" } });
  return result.stdout.trim();
}
