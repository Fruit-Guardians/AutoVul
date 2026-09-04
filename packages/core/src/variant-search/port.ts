import type {
  MissingCheckAnalyzerProvenance,
  RunId,
  VariantCandidate,
  VariantSearchBudget,
  VariantSearchGap,
  VariantSearchInput,
  VerificationLevel,
} from "@autovul/contracts";

export interface VariantSeedPatternFacts {
  readonly capability: "missing_check";
  readonly seedRunId: RunId;
  readonly seedDigest: string;
  readonly seedVerificationLevel: VerificationLevel;
  readonly analyzerProvenance: MissingCheckAnalyzerProvenance;
  readonly primarySymbol: string;
  readonly checkSymbol: string;
  readonly matchedSymbols: readonly string[];
  readonly enclosingFunction?: string;
  readonly targetFingerprints?: {
    readonly vulnerable: string;
    readonly fixed?: string;
  };
}

export interface VariantSearchPortRequest {
  readonly input: VariantSearchInput;
  readonly seedFacts: VariantSeedPatternFacts;
  readonly resolvedBudget: VariantSearchBudget;
}

export interface VariantSearchPortObservation {
  readonly candidates: readonly VariantCandidate[];
  readonly completeness: "complete" | "partial";
  readonly gaps: readonly VariantSearchGap[];
  readonly budgetExhausted: boolean;
  readonly targetsInspected: number;
  readonly filesInspected: number;
  readonly evidenceRefs: readonly string[];
  readonly analyzer: {
    readonly analyzer_id: "variant_search_git";
    readonly evidence_kind: "real_analyzer";
    readonly version: string;
    readonly adapter_version: string;
  };
}

export interface VariantSearchPort {
  search(
    request: VariantSearchPortRequest,
    options: { readonly signal?: AbortSignal },
  ): Promise<VariantSearchPortObservation>;
}

export function unavailableVariantSearchPort(): VariantSearchPort {
  return {
    async search() {
      throw new Error("Variant search analyzer is not configured on this application instance");
    },
  };
}
