import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { DomainError } from "@autovul/contracts";
import { GitVariantSearchAdapter } from "@autovul/codeql-runner";
import type { VariantSearchPortRequest } from "@autovul/core";

const execFile = promisify(execFileCallback);

async function git(repository: string, args: readonly string[]): Promise<void> {
  await execFile("git", [...args], { cwd: repository, env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" } });
}

async function gitOutput(repository: string, args: readonly string[]): Promise<string> {
  const result = await execFile("git", [...args], { cwd: repository, env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" } });
  return result.stdout.trim();
}

describe("GitVariantSearchAdapter", () => {
  it("discovers candidate locations in a real git repository", async () => {
    const repository = await mkdtemp(join(tmpdir(), "autovul-variant-search-"));
    try {
      await git(repository, ["init", "--initial-branch=main"]);
      await git(repository, ["config", "user.email", "variant-test@example.invalid"]);
      await git(repository, ["config", "user.name", "Variant Test"]);
      await mkdir(join(repository, "src", "auth"), { recursive: true });

      await writeFile(
        join(repository, "src", "auth", "token.ts"),
        "export function tokenHandler(req: any) {\n  handleSigninTokenExchangeInvoke(req);\n}\n",
        "utf8",
      );
      await writeFile(
        join(repository, "src", "auth", "device.ts"),
        "export function deviceHandler(req: any) {\n  handleSigninTokenExchangeInvoke(req);\n}\n",
        "utf8",
      );
      await writeFile(
        join(repository, "src", "auth", "profile.ts"),
        "export function profileHandler(req: any) {\n  getProfile(req);\n}\n",
        "utf8",
      );

      await git(repository, ["add", "."]);
      await git(repository, ["commit", "-m", "initial"]);
      const headOid = await gitOutput(repository, ["rev-parse", "HEAD"]);

      const adapter = new GitVariantSearchAdapter({ trustedRoots: [repository] });
      const request: VariantSearchPortRequest = {
        input: {
          seed_run_id: "run_seed123",
          corpus: [
            {
              kind: "git_revision",
              repository,
              revision: headOid,
            },
          ],
          strategy: "symbol_call_pattern",
        },
        seedFacts: {
          capability: "missing_check",
          matchedSymbols: ["handleSigninTokenExchangeInvoke"],
          primarySymbol: "handleSigninTokenExchangeInvoke",
        },
        resolvedBudget: {
          max_candidates: 50,
          max_files_per_target: 100,
          timeout_ms: 30_000,
        },
      };

      const observation = await adapter.search(request, {});
      expect(observation.candidates).toHaveLength(2);
      expect(observation.budgetExhausted).toBe(false);
      expect(observation.analyzer.analyzer_id).toBe("variant_search_git");
      expect(observation.candidates.map((c) => c.location.file)).toEqual([
        "src/auth/device.ts",
        "src/auth/token.ts",
      ]);
      expect(observation.candidates[0].location.start_line).toBe(2);
      expect(observation.candidates[0].location.enclosing_symbol).toBe("deviceHandler");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  it("enforces candidate budget limit", async () => {
    const repository = await mkdtemp(join(tmpdir(), "autovul-variant-budget-"));
    try {
      await git(repository, ["init", "--initial-branch=main"]);
      await git(repository, ["config", "user.email", "variant-test@example.invalid"]);
      await git(repository, ["config", "user.name", "Variant Test"]);
      await mkdir(join(repository, "src"), { recursive: true });

      await writeFile(
        join(repository, "src", "one.ts"),
        "function a() { executeSink(); }\n",
        "utf8",
      );
      await writeFile(
        join(repository, "src", "two.ts"),
        "function b() { executeSink(); }\n",
        "utf8",
      );

      await git(repository, ["add", "."]);
      await git(repository, ["commit", "-m", "initial"]);
      const headOid = await gitOutput(repository, ["rev-parse", "HEAD"]);

      const adapter = new GitVariantSearchAdapter({ trustedRoots: [repository] });
      const request: VariantSearchPortRequest = {
        input: {
          seed_run_id: "run_seed123",
          corpus: [{ kind: "git_revision", repository, revision: headOid }],
          strategy: "symbol_call_pattern",
        },
        seedFacts: {
          capability: "flow",
          matchedSymbols: ["executeSink"],
          primarySymbol: "executeSink",
        },
        resolvedBudget: {
          max_candidates: 1,
          max_files_per_target: 100,
          timeout_ms: 30_000,
        },
      };

      const observation = await adapter.search(request, {});
      expect(observation.candidates).toHaveLength(1);
      expect(observation.budgetExhausted).toBe(true);
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  it("rejects untrusted repository paths", async () => {
    const trustedRoot = await mkdtemp(join(tmpdir(), "autovul-trusted-"));
    const untrustedRepo = await mkdtemp(join(tmpdir(), "autovul-untrusted-"));
    try {
      const adapter = new GitVariantSearchAdapter({ trustedRoots: [trustedRoot] });
      const request: VariantSearchPortRequest = {
        input: {
          seed_run_id: "run_seed123",
          corpus: [{ kind: "git_revision", repository: untrustedRepo, revision: "abc" }],
          strategy: "symbol_call_pattern",
        },
        seedFacts: { capability: "flow", matchedSymbols: ["sink"] },
        resolvedBudget: { max_candidates: 10, max_files_per_target: 10, timeout_ms: 10_000 },
      };

      await expect(adapter.search(request, {})).rejects.toMatchObject<Partial<DomainError>>({
        code: "CHANGE_OBSERVATION_REPOSITORY_UNTRUSTED",
      });
    } finally {
      await rm(trustedRoot, { recursive: true, force: true });
      await rm(untrustedRepo, { recursive: true, force: true });
    }
  });

  it("discovers candidates across TSX, arrow function properties, and enclosing_signature strategy", async () => {
    const repository = await mkdtemp(join(tmpdir(), "autovul-variant-tsx-"));
    try {
      await git(repository, ["init", "--initial-branch=main"]);
      await git(repository, ["config", "user.email", "variant-test@example.invalid"]);
      await git(repository, ["config", "user.name", "Variant Test"]);
      await mkdir(join(repository, "src"), { recursive: true });

      await writeFile(
        join(repository, "src", "Component.tsx"),
        "export const AuthButton = () => {\n  const onClick = () => (authenticateUser)();\n  return <button onClick={onClick} />;\n};\n",
        "utf8",
      );
      await writeFile(
        join(repository, "src", "types.d.ts"),
        "export declare function authenticateUser(): void;\n",
        "utf8",
      );

      await git(repository, ["add", "."]);
      await git(repository, ["commit", "-m", "add tsx and dts"]);
      const headOid = await gitOutput(repository, ["rev-parse", "HEAD"]);

      const adapter = new GitVariantSearchAdapter({ trustedRoots: [repository] });

      // 1. Call pattern with parenthesized expression in TSX
      const callObs = await adapter.search({
        input: {
          seed_run_id: "run_seed123",
          corpus: [{ kind: "git_revision", repository, revision: headOid }],
          strategy: "symbol_call_pattern",
        },
        seedFacts: {
          capability: "flow",
          matchedSymbols: ["authenticateUser"],
          primarySymbol: "authenticateUser",
        },
        resolvedBudget: { max_candidates: 10, max_files_per_target: 10, timeout_ms: 10_000 },
      }, {});

      expect(callObs.candidates).toHaveLength(1);
      expect(callObs.candidates[0].location.file).toBe("src/Component.tsx");
      expect(callObs.candidates[0].location.enclosing_symbol).toBe("onClick");

      // 2. Enclosing signature strategy
      const sigObs = await adapter.search({
        input: {
          seed_run_id: "run_seed123",
          corpus: [{ kind: "git_revision", repository, revision: headOid }],
          strategy: "enclosing_signature",
        },
        seedFacts: {
          capability: "missing_check",
          matchedSymbols: ["AuthButton"],
          primarySymbol: "AuthButton",
        },
        resolvedBudget: { max_candidates: 10, max_files_per_target: 10, timeout_ms: 10_000 },
      }, {});

      expect(sigObs.candidates).toHaveLength(1);
      expect(sigObs.candidates[0].location.file).toBe("src/Component.tsx");
      expect(sigObs.candidates[0].location.enclosing_symbol).toBe("AuthButton");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });
});
