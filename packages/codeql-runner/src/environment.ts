/**
 * Typed compatibility lookup for configuration that crossed the project rename.
 * The canonical AutoVul name always wins; the former name is read only as a
 * deprecated fallback and values are never logged by this helper.
 */
export type AutovulEnvironmentKey =
  | "RUNS_DIR"
  | "TIMEOUT_MS"
  | `M2_${string}`
  | `M4_${string}`
  | `PI_${string}`;

export function readAutovulEnv(
  key: AutovulEnvironmentKey,
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  const canonical = env[`AUTOVUL_${key}`];
  if (canonical !== undefined) return canonical;
  const legacyName = key === "RUNS_DIR" ? "PURE_AUTO_CODEQL_V2_RUNS_DIR" : `PURE_AUTO_CODEQL_${key}`;
  return env[legacyName];
}
