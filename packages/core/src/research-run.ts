import { Value } from "typebox/value";

import {
  AutovulRunToolInputSchema,
  DomainError,
  type AutovulRunToolInput,
  type ResearchExecutionResult,
  type MissingCheckExecutionResult,
  type ChangeObservationExecutionResult,
  type ChangeObservationReplayComparison,
  type TypestateReplayComparison,
  type RunManifest,
} from "@autovul/contracts";

import type { ArtifactStorePort, CodeqlOperationOptions } from "./ports.js";
import { readResearchOperationRoute } from "./research-operation.js";
import { RunStatusService } from "./status-service.js";
import { RunCancellationService } from "./run-cancellation.js";
import { FlowReplayService } from "./flow/replay.js";
import { MissingCheckReplayService } from "./missing-check/replay.js";
import { TypestateReplayService } from "./typestate/replay.js";
import { ChangeObservationReplayService } from "./change-observation/replay.js";

export type RunManagementResult = RunManifest | ResearchExecutionResult | MissingCheckExecutionResult | TypestateReplayComparison | ChangeObservationExecutionResult | ChangeObservationReplayComparison;

/**
 * Shared run management owns status, cancellation and route lookup only.
 * Capability replay remains an explicit static branch; domain semantics do
 * not move into a shared registry or generic state-machine abstraction.
 */
export class ResearchRunService {
  constructor(
    private readonly status: RunStatusService,
    private readonly artifacts: ArtifactStorePort,
    private readonly flowReplay: FlowReplayService,
    private readonly missingCheckReplay: MissingCheckReplayService,
    private readonly typestateReplay: TypestateReplayService,
    private readonly changeObservationReplay: ChangeObservationReplayService,
    private readonly cancellations: RunCancellationService,
  ) {}

  async manage(input: unknown, options: CodeqlOperationOptions): Promise<RunManagementResult> {
    if (!Value.Check(AutovulRunToolInputSchema, input)) {
      throw new DomainError("INVALID_INPUT", "input", "autovul_run input is invalid", false);
    }
    const request = Value.Parse(AutovulRunToolInputSchema, input) as AutovulRunToolInput;
    if (request.action === "status") return this.status.get(request.run_id);
    if (request.action === "cancel") {
      this.cancellations.cancel(request.run_id);
      return this.status.cancel(
        request.run_id,
        new DomainError("PROCESS_CANCELLED", "process", `Run ${request.run_id} was cancelled`, false, { runId: request.run_id }).toRecord(),
      );
    }
    const route = await readResearchOperationRoute(this.artifacts, request.run_id).catch(() => undefined);
    if (route?.route_kind === "capability" && route.capability === "flow") return this.flowReplay.replay(request.run_id, route, options);
    if (route?.route_kind === "capability" && route.capability === "missing_check") return this.missingCheckReplay.replay(request.run_id, route, options);
    if (route?.route_kind === "capability" && route.capability === "typestate") return this.typestateReplay.replay(request.run_id, route, options);
    if (route?.route_kind === "analyzer_service" && route.service === "change_observation") return this.changeObservationReplay.replay(request.run_id, route, options);
    // Explicit routing, not a generic capability registry.
    return this.flowReplay.blocked(request.run_id, route === undefined ? "RESEARCH_REPLAY_ROUTE_MISSING" : "RESEARCH_REPLAY_ROUTE_UNSUPPORTED", ["stop"]);
  }
}
