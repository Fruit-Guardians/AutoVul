import {
  DomainError,
  type DynamicReproductionExecutionObservation,
  type DynamicReproductionExecutionRequest,
} from "@autovul/contracts";

export const SAFE_SYSTEM_EXECUTABLES: ReadonlySet<string> = new Set([
  "node",
  "python3",
  "python",
  "git",
]);

export const FORBIDDEN_ENV_VARS: ReadonlySet<string> = new Set([
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "NODE_OPTIONS",
  "PERL5OPT",
  "PERL5LIB",
  "PYTHONPATH",
  "RUBYOPT",
]);

export const SAFE_BASE_ENV_VARS: readonly string[] = [
  "PATH",
  "HOME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TMPDIR",
  "TEMP",
  "TMP",
  "NODE_PATH",
];

export interface DynamicReproductionPortOptions {
  readonly signal?: AbortSignal;
  readonly trustedRoots: readonly string[];
}

export interface DynamicReproductionPort {
  execute(
    request: DynamicReproductionExecutionRequest,
    options: DynamicReproductionPortOptions,
  ): Promise<DynamicReproductionExecutionObservation>;
}

export function unavailableDynamicReproductionPort(): DynamicReproductionPort {
  return {
    async execute() {
      throw new DomainError(
        "INVALID_STATE_TRANSITION",
        "state",
        "Dynamic reproduction runner is not configured on this application instance",
        false,
      );
    },
  };
}

export function validateReproductionEnvironment(
  customEnv?: Readonly<Record<string, string>>,
): void {
  if (!customEnv) return;
  for (const key of Object.keys(customEnv)) {
    const upper = key.toUpperCase();
    if (FORBIDDEN_ENV_VARS.has(upper)) {
      throw new DomainError(
        "DYN_UNSAFE_ENVIRONMENT",
        "policy",
        `Disallowed loader or interpreter injection environment variable: ${key}`,
        false,
        { key },
      );
    }
    if (upper.includes("TOKEN") || upper.includes("SECRET") || upper.includes("API_KEY") || upper.includes("PASSWORD")) {
      throw new DomainError(
        "DYN_UNSAFE_ENVIRONMENT",
        "policy",
        `Potential secret credential variable in environment: ${key}`,
        false,
        { key },
      );
    }
  }
}
