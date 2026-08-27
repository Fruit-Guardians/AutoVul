import {
  asDomainError,
  DomainError,
  parseSchema,
  ProbeEvidenceSchema,
  RunIdSchema,
  type ProbeEvidence,
} from "@pure-auto-codeql/contracts";

import type { CodeqlOperationOptions } from "../ports.js";
import { normalizeTaintIntent } from "../language-packs.js";
import type { CodeqlWorkflowContext } from "./context.js";
import { boundedOperationOptions, isTerminalWorkflowStatus } from "./status.js";

export async function probeQuery(
  context: CodeqlWorkflowContext,
  inputRunId: unknown,
  inputIntent: unknown,
  options: CodeqlOperationOptions,
): Promise<ProbeEvidence> {
  const runId = parseSchema(RunIdSchema, inputRunId, "run id");
  try {
    return await context.repository.withRunOperation(runId, options, async () => {
      const state = await context.repository.load(runId);
      const intent = normalizeTaintIntent(inputIntent, state.spec.language);
      const run = await context.repository.getRun(runId);
      if (isTerminalWorkflowStatus(run.status)) {
        throw newDomainStateError(runId, run.status);
      }
      if (run.status === "created" || run.status === "checkpointed") {
        await context.repository.startRun(runId, "query_probe");
      }
      const evidence = parseSchema(
        ProbeEvidenceSchema,
        await context.probes.executeProbe(
          {
            runId,
            intent,
            spec: state.spec,
            artifactRoot: context.repository.artifactRoot(runId),
          },
          boundedOperationOptions(options, state.spec.timeout_ms),
        ),
        "probe evidence",
      );
      await context.repository.writeArtifact(runId, `probes/${intent.intent_id}/probe-evidence.json`, `${JSON.stringify(evidence, null, 2)}\n`);
      return evidence;
    });
  } catch (error: unknown) {
    const domainError = asDomainError(error);
    const withId = addRunId(domainError, runId);
    if (withId.code === "PROCESS_CANCELLED" && withId.details.waitingForWorkflowLease !== true) {
      await context.repository.cancelRun(runId, withId.toRecord()).catch(() => undefined);
    } else if (withId.category !== "input" && withId.code !== "WORKFLOW_BUSY") {
      await context.repository.failRun(runId, withId.toRecord()).catch(() => undefined);
    }
    throw withId;
  }
}

function newDomainStateError(runId: string, status: string): DomainError {
  return new DomainError("INVALID_STATE_TRANSITION", "state", `Cannot probe in ${status} run`, false, { runId, status });
}

function addRunId(error: DomainError, runId: string): DomainError {
  if (error.details.runId === runId) return error;
  return new DomainError(error.code, error.category, error.message, error.retryable, { ...error.details, runId });
}
