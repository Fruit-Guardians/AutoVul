import { describe, expect, it } from "vitest";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DomainError,
  parseSchema,
  DynamicReproductionExecutionObservationSchema,
  type DynamicReproductionExecutionRequest,
} from "@autovul/contracts";
import {
  DynamicReproductionReplayService,
  unavailableDynamicReproductionPort,
  validateReproductionEnvironment,
} from "@autovul/core";
import {
  ControlledDynamicReproductionAdapter,
  LocalArtifactStore,
  NodeFileSystemPort,
} from "@autovul/codeql-runner";

describe("Controlled Dynamic Reproduction Port", () => {
  async function createFixture() {
    const root = join(
      tmpdir(),
      `autovul-dynrepro-${Math.random().toString(36).slice(2, 8)}`,
    );
    const workspaceDir = join(root, "target-workspace");
    const runsDir = join(root, "runs");
    const untrustedDir = join(root, "untrusted-dir");

    await mkdir(workspaceDir, { recursive: true });
    await mkdir(runsDir, { recursive: true });
    await mkdir(untrustedDir, { recursive: true });

    const filesystem = new NodeFileSystemPort();
    const artifacts = new LocalArtifactStore(runsDir, filesystem);
    const adapter = new ControlledDynamicReproductionAdapter(artifacts);
    const replayService = new DynamicReproductionReplayService(artifacts);

    return {
      root,
      workspaceDir,
      runsDir,
      untrustedDir,
      artifacts,
      adapter,
      replayService,
      cleanup: async () => {
        await rm(root, { recursive: true, force: true });
      },
    };
  }

  it("REQ-DYNPORT-001: unavailable port throws structured INVALID_STATE_TRANSITION", async () => {
    const port = unavailableDynamicReproductionPort();
    await expect(
      port.execute(
        {} as unknown as DynamicReproductionExecutionRequest,
        { trustedRoots: [] },
      ),
    ).rejects.toThrow(DomainError);
  });

  it("REQ-DYNPORT-002 & REQ-DYNPORT-009: executes safe reproduction command and produces valid observation", async () => {
    const fixture = await createFixture();
    try {
      const scriptPath = join(fixture.workspaceDir, "repro.js");
      await writeFile(
        scriptPath,
        'console.log("EXPLOIT_SUCCESSFUL_WITNESS"); process.exit(0);',
        "utf8",
      );

      const request: DynamicReproductionExecutionRequest = {
        run_id: "run_dyn_test_01",
        hypothesis_id: "hypo-dyn-01",
        command: {
          executable: "node",
          args: [scriptPath],
          cwd: fixture.workspaceDir,
        },
        budget: {
          timeout_ms: 5000,
          max_output_bytes: 4096,
        },
        artifact_root: fixture.runsDir,
      };

      const observation = await fixture.adapter.execute(request, {
        trustedRoots: [fixture.workspaceDir],
      });

      expect(observation.exit_code).toBe(0);
      expect(observation.signal).toBeNull();
      expect(observation.timed_out).toBe(false);
      expect(observation.cancelled).toBe(false);
      expect(observation.stdout).toContain("EXPLOIT_SUCCESSFUL_WITNESS");
      expect(observation.environment_digest).toMatch(/^[0-9a-f]{64}$/);
      expect(observation.evidence_ref).toBe("reproduction/hypo-dyn-01/witnesses.json");

      // Verify schema conformity
      const validated = parseSchema(
        DynamicReproductionExecutionObservationSchema,
        observation,
        "observation schema",
      );
      expect(validated.exit_code).toBe(0);

      // Verify artifacts persisted
      const savedObs = await fixture.artifacts.readArtifact(
        "run_dyn_test_01",
        "reproduction/hypo-dyn-01/observation.json",
      );
      expect(savedObs).toBeDefined();
    } finally {
      await fixture.cleanup();
    }
  });

  it("REQ-DYNPORT-003: rejects working directory or executable outside trusted roots", async () => {
    const fixture = await createFixture();
    try {
      const request: DynamicReproductionExecutionRequest = {
        run_id: "run_dyn_untrusted",
        hypothesis_id: "hypo-untrusted",
        command: {
          executable: "node",
          args: ["-e", "process.exit(0)"],
          cwd: fixture.untrustedDir,
        },
        budget: {
          timeout_ms: 5000,
          max_output_bytes: 4096,
        },
        artifact_root: fixture.runsDir,
      };

      await expect(
        fixture.adapter.execute(request, {
          trustedRoots: [fixture.workspaceDir],
        }),
      ).rejects.toThrowError(/outside trusted roots/);

      // Also test executable path outside trusted roots
      const externalScript = join(fixture.untrustedDir, "external.js");
      await writeFile(externalScript, "process.exit(0);", "utf8");

      const request2: DynamicReproductionExecutionRequest = {
        run_id: "run_dyn_untrusted_exec",
        hypothesis_id: "hypo-untrusted-exec",
        command: {
          executable: externalScript,
          args: [],
          cwd: fixture.workspaceDir,
        },
        budget: {
          timeout_ms: 5000,
          max_output_bytes: 4096,
        },
        artifact_root: fixture.runsDir,
      };

      await expect(
        fixture.adapter.execute(request2, {
          trustedRoots: [fixture.workspaceDir],
        }),
      ).rejects.toThrowError(/outside trusted roots/);
    } finally {
      await fixture.cleanup();
    }
  });

  it("REQ-DYNPORT-004: disallows unapproved system executables", async () => {
    const fixture = await createFixture();
    try {
      const request: DynamicReproductionExecutionRequest = {
        run_id: "run_dyn_bad_bin",
        hypothesis_id: "hypo-bad-bin",
        command: {
          executable: "bash",
          args: ["-c", "echo hello"],
          cwd: fixture.workspaceDir,
        },
        budget: {
          timeout_ms: 5000,
          max_output_bytes: 4096,
        },
        artifact_root: fixture.runsDir,
      };

      await expect(
        fixture.adapter.execute(request, {
          trustedRoots: [fixture.workspaceDir],
        }),
      ).rejects.toThrow(DomainError);
    } finally {
      await fixture.cleanup();
    }
  });

  it("REQ-DYNPORT-005: detects and rejects dangerous environment variables and credential tokens", async () => {
    expect(() =>
      validateReproductionEnvironment({ NODE_OPTIONS: "--require /tmp/evil.js" }),
    ).toThrow(DomainError);

    expect(() =>
      validateReproductionEnvironment({ LD_PRELOAD: "/tmp/evil.so" }),
    ).toThrow(DomainError);

    expect(() =>
      validateReproductionEnvironment({ GITHUB_TOKEN: "ghp_1234567890" }),
    ).toThrow(DomainError);

    expect(() =>
      validateReproductionEnvironment({ API_KEY_SECRET: "secret123" }),
    ).toThrow(DomainError);

    // Safe variables allowed
    expect(() =>
      validateReproductionEnvironment({ TARGET_PORT: "9000", MODE: "test" }),
    ).not.toThrow();
  });

  it("REQ-DYNPORT-006: terminates child process tree upon timeout or cancellation", async () => {
    const fixture = await createFixture();
    try {
      const hangScript = join(fixture.workspaceDir, "hang.js");
      await writeFile(
        hangScript,
        `
        const { spawn } = require("node:child_process");
        // Spawn background worker to test tree termination
        spawn("node", ["-e", "while(true){}"], { stdio: "ignore" });
        while(true) {}
        `,
        "utf8",
      );

      const request: DynamicReproductionExecutionRequest = {
        run_id: "run_dyn_timeout",
        hypothesis_id: "hypo-timeout",
        command: {
          executable: "node",
          args: [hangScript],
          cwd: fixture.workspaceDir,
        },
        budget: {
          timeout_ms: 300,
          max_output_bytes: 4096,
        },
        artifact_root: fixture.runsDir,
      };

      const start = Date.now();
      const observation = await fixture.adapter.execute(request, {
        trustedRoots: [fixture.workspaceDir],
      });
      const duration = Date.now() - start;

      expect(observation.timed_out).toBe(true);
      expect(duration).toBeLessThan(3000);

      // Test cancellation with AbortController
      const abortController = new AbortController();
      const cancelPromise = fixture.adapter.execute(request, {
        signal: abortController.signal,
        trustedRoots: [fixture.workspaceDir],
      });
      abortController.abort();
      const cancelObs = await cancelPromise;
      expect(cancelObs.cancelled).toBe(true);
    } finally {
      await fixture.cleanup();
    }
  });

  it("REQ-DYNPORT-007: bounds stdout/stderr output and redacts detected secrets", async () => {
    const fixture = await createFixture();
    try {
      const scriptPath = join(fixture.workspaceDir, "output_secrets.js");
      await writeFile(
        scriptPath,
        `
        console.log("token: super_secret_12345");
        console.log("bearer my_bearer_token_abcdef");
        console.log("A".repeat(5000));
        `,
        "utf8",
      );

      const request: DynamicReproductionExecutionRequest = {
        run_id: "run_dyn_secrets",
        hypothesis_id: "hypo-secrets",
        command: {
          executable: "node",
          args: [scriptPath],
          cwd: fixture.workspaceDir,
        },
        budget: {
          timeout_ms: 5000,
          max_output_bytes: 512,
        },
        artifact_root: fixture.runsDir,
      };

      const observation = await fixture.adapter.execute(request, {
        trustedRoots: [fixture.workspaceDir],
      });

      expect(observation.stdout_truncated).toBe(true);
      expect(observation.stdout.length).toBeLessThanOrEqual(512);
      expect(observation.stdout).not.toContain("super_secret_12345");
      expect(observation.stdout).toContain("[REDACTED]");
    } finally {
      await fixture.cleanup();
    }
  });

  it("REQ-DYNPORT-008: captures witness artifacts and rejects directory traversal", async () => {
    const fixture = await createFixture();
    try {
      const scriptPath = join(fixture.workspaceDir, "witness_gen.js");
      await writeFile(
        scriptPath,
        `
        const fs = require("node:fs");
        fs.writeFileSync("repro-witness.json", JSON.stringify({ exploited: true, timestamp: 123 }));
        `,
        "utf8",
      );

      const request: DynamicReproductionExecutionRequest = {
        run_id: "run_dyn_witness",
        hypothesis_id: "hypo-witness",
        command: {
          executable: "node",
          args: [scriptPath],
          cwd: fixture.workspaceDir,
        },
        budget: {
          timeout_ms: 5000,
          max_output_bytes: 4096,
        },
        witness_file_paths: ["repro-witness.json"],
        artifact_root: fixture.runsDir,
      };

      const observation = await fixture.adapter.execute(request, {
        trustedRoots: [fixture.workspaceDir],
      });

      expect(observation.witnesses).toHaveLength(1);
      const witness = observation.witnesses[0];
      expect(witness.path).toBe("repro-witness.json");
      expect(witness.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(witness.snippet).toContain("exploited");

      // Verify artifact saved in runsDir
      const storedWitness = await fixture.artifacts.readArtifact(
        "run_dyn_witness",
        "reproduction/hypo-witness/witnesses/repro-witness.json",
      );
      expect(storedWitness).toContain("exploited");

      // Test directory traversal rejection
      const escapeRequest: DynamicReproductionExecutionRequest = {
        ...request,
        witness_file_paths: ["../../etc/passwd"],
      };

      await expect(
        fixture.adapter.execute(escapeRequest, {
          trustedRoots: [fixture.workspaceDir],
        }),
      ).rejects.toThrowError(/escapes working directory/);
    } finally {
      await fixture.cleanup();
    }
  });

  it("REQ-DYNPORT-010: model-free replay verifies evidence immutability and detects tampering", async () => {
    const fixture = await createFixture();
    try {
      const scriptPath = join(fixture.workspaceDir, "witness_for_replay.js");
      await writeFile(
        scriptPath,
        'const fs = require("node:fs"); fs.writeFileSync("witness.txt", "trusted_payload_hash_test");',
        "utf8",
      );

      const request: DynamicReproductionExecutionRequest = {
        run_id: "run_dyn_replay",
        hypothesis_id: "hypo-replay",
        command: {
          executable: "node",
          args: [scriptPath],
          cwd: fixture.workspaceDir,
        },
        budget: {
          timeout_ms: 5000,
          max_output_bytes: 4096,
        },
        witness_file_paths: ["witness.txt"],
        artifact_root: fixture.runsDir,
      };

      await fixture.adapter.execute(request, {
        trustedRoots: [fixture.workspaceDir],
      });

      // 1. Initial replay passes as "identical"
      const replayResult1 = await fixture.replayService.verifyReplay(
        "run_dyn_replay",
        "hypo-replay",
      );
      expect(replayResult1.status).toBe("identical");
      expect(replayResult1.checked_witnesses_count).toBe(1);

      // 2. Tamper with the saved witness file in the artifact store
      await fixture.artifacts.writeArtifact(
        "run_dyn_replay",
        "reproduction/hypo-replay/witnesses/witness.txt",
        "tampered_payload_content",
      );

      // 3. Subsequent replay detects mutation
      const replayResult2 = await fixture.replayService.verifyReplay(
        "run_dyn_replay",
        "hypo-replay",
      );
      expect(replayResult2.status).toBe("evidence_mutated");
      expect(replayResult2.detail).toContain("Witness artifact digest mismatch");
    } finally {
      await fixture.cleanup();
    }
  });

  it("differential reproduction: captures witness on vulnerable target and proves mitigation on fixed target", async () => {
    const fixture = await createFixture();
    try {
      const vulnDir = join(fixture.workspaceDir, "vuln-version");
      const fixedDir = join(fixture.workspaceDir, "fixed-version");
      await mkdir(vulnDir, { recursive: true });
      await mkdir(fixedDir, { recursive: true });

      // Vulnerable handler: executes unauthorized token exchange and creates exploit artifact
      const vulnHandler = join(vulnDir, "handler.js");
      await writeFile(
        vulnHandler,
        `
        const fs = require("node:fs");
        // No check: token exchange occurs
        fs.writeFileSync("token-exchange.witness", "UNAUTHORIZED_TOKEN_ISSUED");
        process.exit(0);
        `,
        "utf8",
      );

      // Fixed handler: checks authorization, rejects unauthorized token exchange, exits with code 1
      const fixedHandler = join(fixedDir, "handler.js");
      await writeFile(
        fixedHandler,
        `
        const isAuthorized = false;
        if (!isAuthorized) {
          console.error("403 Forbidden: Signin invoke unauthorized");
          process.exit(1);
        }
        `,
        "utf8",
      );

      // 1. Run vulnerable reproduction
      const vulnRequest: DynamicReproductionExecutionRequest = {
        run_id: "run_diff_vuln",
        hypothesis_id: "hypo-diff-43572",
        command: {
          executable: "node",
          args: [vulnHandler],
          cwd: vulnDir,
        },
        budget: {
          timeout_ms: 5000,
          max_output_bytes: 4096,
        },
        witness_file_paths: ["token-exchange.witness"],
        artifact_root: fixture.runsDir,
      };

      const vulnObs = await fixture.adapter.execute(vulnRequest, {
        trustedRoots: [fixture.workspaceDir],
      });

      expect(vulnObs.exit_code).toBe(0);
      expect(vulnObs.witnesses).toHaveLength(1);
      expect(vulnObs.witnesses[0].path).toBe("token-exchange.witness");
      expect(vulnObs.witnesses[0].snippet).toContain("UNAUTHORIZED_TOKEN_ISSUED");

      // 2. Run fixed reproduction
      const fixedRequest: DynamicReproductionExecutionRequest = {
        run_id: "run_diff_fixed",
        hypothesis_id: "hypo-diff-43572-fixed",
        command: {
          executable: "node",
          args: [fixedHandler],
          cwd: fixedDir,
        },
        budget: {
          timeout_ms: 5000,
          max_output_bytes: 4096,
        },
        witness_file_paths: ["token-exchange.witness"],
        artifact_root: fixture.runsDir,
      };

      const fixedObs = await fixture.adapter.execute(fixedRequest, {
        trustedRoots: [fixture.workspaceDir],
      });

      // Fixed version exited with error (403 Forbidden), produced no witness file
      expect(fixedObs.exit_code).toBe(1);
      expect(fixedObs.stderr).toContain("403 Forbidden");
      expect(fixedObs.witnesses).toHaveLength(0);
    } finally {
      await fixture.cleanup();
    }
  });
});

