import type { RunId } from "@autovul/contracts";

/**
 * Delivers an immediate abort to a bounded operation that is alive in this
 * process. Persisted run status remains the recovery source of truth.
 */
export class RunCancellationService {
  private readonly active = new Map<RunId, AbortController>();

  begin(runId: RunId, parentSignal?: AbortSignal): { readonly signal: AbortSignal; release(): void } {
    const controller = new AbortController();
    const abortFromParent = (): void => controller.abort(parentSignal?.reason);
    if (parentSignal?.aborted) abortFromParent();
    else parentSignal?.addEventListener("abort", abortFromParent, { once: true });
    this.active.set(runId, controller);
    return {
      signal: controller.signal,
      release: (): void => {
        parentSignal?.removeEventListener("abort", abortFromParent);
        if (this.active.get(runId) === controller) this.active.delete(runId);
      },
    };
  }

  cancel(runId: RunId): boolean {
    const controller = this.active.get(runId);
    if (controller === undefined || controller.signal.aborted) return false;
    controller.abort(new Error(`Run ${runId} was cancelled`));
    return true;
  }
}
