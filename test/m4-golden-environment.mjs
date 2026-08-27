const ALLOWED_GENERATOR_ENVIRONMENT = [
  "PATH",
  "NODE_PATH",
  "SystemRoot",
  "TMPDIR",
  "TMP",
  "TEMP",
  "PI_CODING_AGENT_DIR",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_BASE_URL",
  "OPENAI_API_KEY",
  "OPENAI_BASE_URL",
  "OPENAI_ORG_ID",
  "OPENAI_PROJECT_ID",
  "PURE_AUTO_CODEQL_M4_API_KEY",
  "PURE_AUTO_CODEQL_M4_API_BASE",
  "PURE_AUTO_CODEQL_M4_MODEL",
  "PURE_AUTO_CODEQL_M4_PROVIDER",
  "PURE_AUTO_CODEQL_M4_TEMPERATURE",
  "PURE_AUTO_CODEQL_M4_MAX_TOKENS",
  "PURE_AUTO_CODEQL_M4_PI_PROVIDER",
  "PURE_AUTO_CODEQL_M4_PI_MODEL",
  "PURE_AUTO_CODEQL_M4_PI_THINKING",
  "PURE_AUTO_CODEQL_M4_PI_NO_EXTENSIONS",
];

export function sanitizedGeneratorEnvironment(environment = process.env) {
  return Object.fromEntries(
    ALLOWED_GENERATOR_ENVIRONMENT
      .filter((key) => environment[key] !== undefined)
      .map((key) => [key, environment[key]]),
  );
}
