import {
  asDomainError,
  CONTRACTS_VERSION,
  parseSchema,
  DatabasePathSchema,
  RunIdSchema,
  withRunId,
  type DatabaseResult,
  type DoctorResult,
  type RunId,
  type RunManifest,
} from "@pure-auto-codeql/contracts";

import { DoctorService } from "./doctor-service.js";
import type { CodeqlOperationOptions } from "./ports.js";
import { RunStatusService } from "./status-service.js";

export class WorkflowController {
  constructor(
    private readonly doctorService: DoctorService,
    private readonly statusService: RunStatusService,
  ) {}

  async doctor(options: CodeqlOperationOptions): Promise<DoctorResult> {
    const run = await this.statusService.create();
    await this.statusService.start(run.runId, "doctor");
    try {
      const environment = await this.doctorService.doctor(options);
      await this.statusService.checkpoint(run.runId, "doctor", "generated");
      const completed = await this.statusService.complete(run.runId, "generated");
      return { schemaVersion: CONTRACTS_VERSION, environment, run: completed };
    } catch (error: unknown) {
      const domainError = withRunId(asDomainError(error), run.runId);
      await this.finishFailure(run.runId, domainError);
      throw domainError;
    }
  }

  async inspectDatabase(input: unknown, options: CodeqlOperationOptions): Promise<DatabaseResult> {
    const path = parseSchema(DatabasePathSchema, input, "database path");
    return this.databaseOperation(path, "inspect", options);
  }

  async validateDatabase(input: unknown, options: CodeqlOperationOptions): Promise<DatabaseResult> {
    const path = parseSchema(DatabasePathSchema, input, "database path");
    return this.databaseOperation(path, "validate", options);
  }

  async status(input: unknown): Promise<RunManifest> {
    const runId = parseSchema(RunIdSchema, input, "run id");
    return this.statusService.get(runId);
  }

  async startRun(input: unknown): Promise<RunManifest> {
    const runId = parseSchema(RunIdSchema, input, "run id");
    return this.statusService.start(runId);
  }

  async resumeRun(input: unknown): Promise<RunManifest> {
    const runId = parseSchema(RunIdSchema, input, "run id");
    return this.statusService.resume(runId);
  }

  private async databaseOperation(
    path: string,
    operation: "inspect" | "validate",
    options: CodeqlOperationOptions,
  ): Promise<DatabaseResult> {
    const run = await this.statusService.create();
    await this.statusService.start(run.runId, operation);
    try {
      const database = operation === "inspect"
        ? await this.doctorService.inspectDatabase(path, options)
        : await this.doctorService.validateDatabase(path, options);
      await this.statusService.checkpoint(run.runId, operation, "generated");
      const completed = await this.statusService.complete(run.runId, "generated");
      return { schemaVersion: CONTRACTS_VERSION, database, run: completed };
    } catch (error: unknown) {
      const domainError = withRunId(asDomainError(error), run.runId);
      await this.finishFailure(run.runId, domainError);
      throw domainError;
    }
  }

  private async finishFailure(
    runId: RunId,
    error: ReturnType<typeof withRunId>,
  ): Promise<void> {
    if (error.code === "PROCESS_CANCELLED") {
      await this.statusService.cancel(runId, error.toRecord());
      return;
    }
    await this.statusService.fail(runId, error.toRecord());
  }
}
