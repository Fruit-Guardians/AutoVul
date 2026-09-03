import { DomainError, type MissingCheckAnalyzerObservation, type MissingCheckTarget } from "@autovul/contracts";

import type { CodeqlOperationOptions } from "../ports.js";
import type { MissingCheckExecutionPort, MissingCheckExecutionRequest } from "./port.js";

/** Composite port multiplexing MissingCheck requests to the designated analyzer adapter. */
export class CompositeMissingCheckExecutionPort implements MissingCheckExecutionPort {
  constructor(
    private readonly adapters: Readonly<Partial<Record<"codeql" | "javascript_cfg", MissingCheckExecutionPort>>>,
  ) {}

  async execute(request: MissingCheckExecutionRequest, options: CodeqlOperationOptions): Promise<MissingCheckAnalyzerObservation> {
    const adapter = this.adapters[request.analyzer_id];
    if (adapter === undefined) {
      return {
        schema_version: "autovul.missing-check/1",
        compile_accepted: "not_run",
        operation: { state: "not_run", locations: [] },
        required_check: { state: "not_run", locations: [] },
        relation: { state: "not_run", unchecked_witnesses: [], checked_witnesses: [] },
        completeness: { vulnerable: { status: "not_run", scope: request.hypothesis.scope, limitations: [] } },
        capability_gaps: [{ code: `MCHECK_${request.analyzer_id.toUpperCase()}_ADAPTER_UNAVAILABLE`, path: "/" }],
        evidence_refs: [],
        analyzer: { analyzer_id: request.analyzer_id, available: false, evidence_kind: "real_analyzer" },
      };
    }
    return adapter.execute(request, options);
  }

  async validateTarget(target: MissingCheckTarget["vulnerable"], options: CodeqlOperationOptions): Promise<string> {
    if (target.kind === "git_revision" && this.adapters.javascript_cfg?.validateTarget) {
      return this.adapters.javascript_cfg.validateTarget(target, options);
    }
    if (this.adapters.codeql?.validateTarget) {
      return this.adapters.codeql.validateTarget(target, options);
    }
    if (target.expected_fingerprint !== undefined) {
      return target.expected_fingerprint;
    }
    const location = target.kind === "git_revision" ? `${target.repository}@${target.revision}` : target.path;
    throw new DomainError(
      "DATABASE_FINGERPRINT_UNAVAILABLE",
      "database",
      `Target fingerprint unavailable for ${location}`,
      false,
      { location },
    );
  }
}
