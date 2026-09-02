import type {
  ChangeObservation,
  ChangeObservationBudget,
  ChangeObservationInput,
  ChangeObservationRevisionIdentity,
} from "@autovul/contracts";

/** Normalized, bounded request passed to the future read-only Git adapter. */
export interface ChangeObservationPortRequest {
  readonly input: ChangeObservationInput;
  readonly resolvedBudget: ChangeObservationBudget;
  readonly normalizedPathFilters: readonly string[];
}

/**
 * Adapter facts deliberately omit Core-owned scope, resolved budget, and
 * fingerprints. They are normalized and validated before becoming public.
 */
export type ChangeObservationPortObservation = Omit<
  ChangeObservation,
  "scope" | "resolved_budget" | "request_fingerprint" | "observation_fingerprint"
>;

export interface ChangeObservationPort {
  observe(
    request: ChangeObservationPortRequest,
    options: { readonly signal?: AbortSignal },
  ): Promise<ChangeObservationPortObservation>;
}

/** Kept explicit so the Core can prove adapter identity matches the requested commits. */
export function sameRequestedRevision(
  input: Pick<ChangeObservationInput, "base_revision" | "head_revision">,
  identity: ChangeObservationRevisionIdentity,
): boolean {
  return input.base_revision === identity.base_oid && input.head_revision === identity.head_oid;
}
