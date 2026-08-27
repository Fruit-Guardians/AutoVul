import {
  DomainError,
  parseSchema,
  QueryWorkflowStateSchema,
  type QueryWorkflowState,
  type RunId,
} from "@pure-auto-codeql/contracts";

import type { ArtifactStorePort } from "../ports.js";
import { upgradeLegacyState } from "./state-migrations.js";

const STATE_PATH = "workflow/state.json";

/**
 * Canonical persistence boundary for workflow state. ArtifactStore remains the
 * atomic filesystem adapter; this repository owns state schema validation and
 * legacy-state migration so command handlers cannot implement their own copy.
 */
export class WorkflowRepository {
  constructor(private readonly artifacts: ArtifactStorePort) {}

  async load(runId: RunId): Promise<QueryWorkflowState> {
    const raw = await this.artifacts.readArtifact(runId, STATE_PATH);
    if (raw === undefined) {
      throw new DomainError(
        "ARTIFACT_NOT_FOUND",
        "artifact",
        `Query workflow state for ${runId} was not found`,
        false,
        { runId },
      );
    }
    try {
      return parseSchema(
        QueryWorkflowStateSchema,
        upgradeLegacyState(JSON.parse(raw) as unknown),
        "query workflow state",
      );
    } catch (error: unknown) {
      if (error instanceof DomainError && error.code === "INVALID_INPUT") {
        throw new DomainError(
          "ARTIFACT_CORRUPT",
          "artifact",
          `Query workflow state for ${runId} is invalid`,
          false,
          { runId, reason: error.message },
        );
      }
      throw error;
    }
  }

  async tryLoad(runId: RunId): Promise<QueryWorkflowState | undefined> {
    const raw = await this.artifacts.readArtifact(runId, STATE_PATH);
    if (raw === undefined) return undefined;
    return parseSchema(
      QueryWorkflowStateSchema,
      upgradeLegacyState(JSON.parse(raw) as unknown),
      "query workflow state",
    );
  }

  async save(runId: RunId, state: QueryWorkflowState): Promise<void> {
    const parsed = parseSchema(
      QueryWorkflowStateSchema,
      state,
      "query workflow state",
    );
    await this.artifacts.writeArtifact(
      runId,
      STATE_PATH,
      `${JSON.stringify(parsed, null, 2)}\n`,
    );
  }

  artifactRoot(runId: RunId): string {
    return this.artifacts.artifactRoot(runId);
  }

  async readArtifact(runId: RunId, relativePath: string): Promise<string | undefined> {
    return this.artifacts.readArtifact(runId, relativePath);
  }

  async writeArtifact(runId: RunId, relativePath: string, content: string): Promise<void> {
    await this.artifacts.writeArtifact(runId, relativePath, content);
  }

  withRunOperation<T>(
    runId: RunId,
    options: Parameters<ArtifactStorePort["withRunOperation"]>[1],
    operation: () => Promise<T>,
  ): Promise<T> {
    return this.artifacts.withRunOperation(runId, options, operation);
  }

  withCaseLock<T>(fingerprint: string, operation: () => Promise<T>): Promise<T> {
    return this.artifacts.withCaseLock(fingerprint, operation);
  }

  findCaseSummary(fingerprint: string) {
    return this.artifacts.findCaseSummary(fingerprint);
  }

  saveCaseSummary(summary: Parameters<ArtifactStorePort["saveCaseSummary"]>[0]) {
    return this.artifacts.saveCaseSummary(summary);
  }
}
