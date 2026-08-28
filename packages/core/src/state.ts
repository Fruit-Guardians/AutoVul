import { DomainError, type RunPhase, type RunStatus } from "@autovul/contracts";

const TRANSITIONS: Readonly<Record<RunStatus, readonly RunStatus[]>> = {
  created: ["running", "failed", "cancelled"],
  running: ["checkpointed", "completed", "failed", "cancelled", "budget_exhausted"],
  checkpointed: ["running", "completed", "failed", "cancelled", "budget_exhausted"],
  completed: [],
  failed: [],
  cancelled: [],
  budget_exhausted: [],
};

export function canTransition(from: RunStatus, to: RunStatus): boolean {
  return TRANSITIONS[from].includes(to);
}

export function assertTransition(from: RunStatus, to: RunStatus): void {
  if (!canTransition(from, to)) {
    throw new DomainError("INVALID_STATE_TRANSITION", "state", `Cannot transition run from ${from} to ${to}`, false, {
      from,
      to,
    });
  }
}

export function phaseOrDefault(phase: RunPhase | undefined): RunPhase {
  return phase ?? "doctor";
}
