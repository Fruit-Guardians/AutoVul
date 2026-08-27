import {
  CONTRACTS_VERSION,
  DomainError,
  RunManifestSchema,
  type DomainErrorRecord,
  type RunId,
  type RunManifest,
  type RunPhase,
  type RunStatus,
  type VerificationLevel,
} from "@pure-auto-codeql/contracts";
import { parseSchema } from "@pure-auto-codeql/contracts";

import type { ArtifactStorePort, ClockPort, IdGeneratorPort } from "./ports.js";
import { assertTransition, phaseOrDefault } from "./state.js";

export class RunStatusService {
  constructor(
    private readonly artifacts: ArtifactStorePort,
    private readonly clock: ClockPort,
    private readonly ids: IdGeneratorPort,
  ) {}

  async create(): Promise<RunManifest> {
    const runId = this.ids.next();
    return this.artifacts.withRunLock(runId, async () => {
      const existing = await this.artifacts.findManifest(runId);
      if (existing) {
        return existing;
      }
      const now = this.clock.now();
      const manifest: RunManifest = {
        schemaVersion: CONTRACTS_VERSION,
        runId,
        status: "created",
        verificationLevel: "generated",
        createdAt: now,
        updatedAt: now,
        artifactRoot: this.artifacts.artifactRoot(runId),
      };
      await this.artifacts.saveManifest(manifest);
      return manifest;
    });
  }

  async get(runId: RunId): Promise<RunManifest> {
    const manifest = await this.artifacts.findManifest(runId);
    if (!manifest) {
      throw new DomainError("ARTIFACT_NOT_FOUND", "artifact", `Run ${runId} was not found`, false, { runId });
    }
    return manifest;
  }

  async start(runId: RunId, phase?: RunPhase): Promise<RunManifest> {
    return this.mutate(runId, (manifest) => {
      if (manifest.status === "running") {
        return manifest;
      }
      if (manifest.status === "completed" || manifest.status === "failed" || manifest.status === "cancelled" || manifest.status === "budget_exhausted") {
        return manifest;
      }
      assertTransition(manifest.status, "running");
      return this.updated(manifest, {
        status: "running",
        phase: phaseOrDefault(phase),
      });
    });
  }

  async checkpoint(runId: RunId, phase: RunPhase, verificationLevel: VerificationLevel): Promise<RunManifest> {
    return this.mutate(runId, (manifest) => {
      if (manifest.status === "checkpointed" && manifest.checkpoint?.phase === phase) {
        return manifest;
      }
      assertTransition(manifest.status, "checkpointed");
      const completedAt = this.clock.now();
      return this.updated(manifest, {
        status: "checkpointed",
        phase,
        verificationLevel,
        checkpoint: { phase, completedAt, verificationLevel },
      });
    });
  }

  async complete(runId: RunId, verificationLevel: VerificationLevel = "generated", phase?: RunPhase): Promise<RunManifest> {
    return this.mutate(runId, (manifest) => {
      if (manifest.status === "completed" || manifest.status === "failed" || manifest.status === "cancelled" || manifest.status === "budget_exhausted") {
        return manifest;
      }
      assertTransition(manifest.status, "completed");
      return this.updated(manifest, {
        status: "completed",
        verificationLevel,
        ...(phase === undefined ? {} : { phase }),
      });
    });
  }

  async fail(runId: RunId, error: DomainErrorRecord): Promise<RunManifest> {
    return this.mutate(runId, (manifest) => {
      if (manifest.status === "failed" || manifest.status === "completed" || manifest.status === "cancelled" || manifest.status === "budget_exhausted") {
        return manifest;
      }
      assertTransition(manifest.status, "failed");
      return this.updated(manifest, { status: "failed", error });
    });
  }

  async cancel(runId: RunId, error?: DomainErrorRecord): Promise<RunManifest> {
    return this.mutate(runId, (manifest) => {
      if (manifest.status === "cancelled" || manifest.status === "completed" || manifest.status === "failed" || manifest.status === "budget_exhausted") {
        return manifest;
      }
      assertTransition(manifest.status, "cancelled");
      return this.updated(manifest, { status: "cancelled", ...(error === undefined ? {} : { error }) });
    });
  }

  async exhaust(runId: RunId, error: DomainErrorRecord): Promise<RunManifest> {
    return this.mutate(runId, (manifest) => {
      if (manifest.status === "budget_exhausted" || manifest.status === "completed" || manifest.status === "failed" || manifest.status === "cancelled") {
        return manifest;
      }
      assertTransition(manifest.status, "budget_exhausted");
      return this.updated(manifest, { status: "budget_exhausted", error });
    });
  }

  /** Repair a projection from authoritative workflow state, including after a stale terminal projection. */
  async reconcileCheckpoint(runId: RunId, phase: RunPhase, verificationLevel: VerificationLevel): Promise<RunManifest> {
    return this.artifacts.withRunLock(runId, async () => this.mutateLocked(runId, (manifest) => {
      const { error: _error, ...withoutError } = manifest;
      return this.updated(withoutError, {
        status: "checkpointed",
        phase,
        verificationLevel,
        checkpoint: { phase, completedAt: this.clock.now(), verificationLevel },
      });
    }));
  }

  /** Repair a completed projection after the authoritative Query Pack commit. */
  async reconcileComplete(runId: RunId, verificationLevel: VerificationLevel, phase: RunPhase): Promise<RunManifest> {
    return this.artifacts.withRunLock(runId, async () => this.mutateLocked(runId, (manifest) => {
      const { error: _error, ...withoutError } = manifest;
      return this.updated(withoutError, { status: "completed", phase, verificationLevel });
    }));
  }

  /** Repair budget exhaustion from committed candidate state. */
  async reconcileExhausted(runId: RunId, error: DomainErrorRecord): Promise<RunManifest> {
    return this.artifacts.withRunLock(runId, async () => this.mutateLocked(runId, (manifest) => {
      const { checkpoint: _checkpoint, ...withoutCheckpoint } = manifest;
      return this.updated(withoutCheckpoint, { status: "budget_exhausted", error });
    }));
  }

  /** Apply a manifest mutation while the caller owns the workflow lease. */
  async mutateLocked(runId: RunId, operation: (manifest: RunManifest) => RunManifest): Promise<RunManifest> {
    const current = await this.get(runId);
    const next = parseSchema(RunManifestSchema, operation(current), "run manifest");
    if (next !== current) {
      await this.artifacts.saveManifest(next);
    }
    return next;
  }

  async resume(runId: RunId): Promise<RunManifest> {
    const manifest = await this.get(runId);
    if (manifest.status === "checkpointed") {
      return this.start(runId, manifest.checkpoint?.phase ?? manifest.phase);
    }
    if (manifest.status === "created") {
      return this.start(runId, manifest.phase);
    }
    return manifest;
  }

  private async mutate(runId: RunId, operation: (manifest: RunManifest) => RunManifest): Promise<RunManifest> {
    return this.artifacts.withRunLock(runId, async () => {
      return this.mutateLocked(runId, operation);
    });
  }

  private updated(manifest: RunManifest, patch: Partial<RunManifest>): RunManifest {
    return {
      ...manifest,
      ...patch,
      updatedAt: this.clock.now(),
    };
  }
}
