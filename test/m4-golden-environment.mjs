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
  "AUTOVUL_M4_API_KEY",
  "AUTOVUL_M4_API_BASE",
  "AUTOVUL_M4_MODEL",
  "AUTOVUL_M4_PROVIDER",
  "AUTOVUL_M4_TEMPERATURE",
  "AUTOVUL_M4_MAX_TOKENS",
  "AUTOVUL_M4_PI_PROVIDER",
  "AUTOVUL_M4_PI_MODEL",
  "AUTOVUL_M4_PI_THINKING",
  "AUTOVUL_M4_PI_NO_EXTENSIONS",
];

export function sanitizedGeneratorEnvironment(environment = process.env) {
  return Object.fromEntries(
    ALLOWED_GENERATOR_ENVIRONMENT.flatMap((key) => {
      if (!key.startsWith("AUTOVUL_")) return environment[key] === undefined ? [] : [[key, environment[key]]];
      const value = readAutovulEnv(key.slice("AUTOVUL_".length), environment);
      return value === undefined ? [] : [[key, value]];
    }),
  );
}
import { readAutovulEnv } from "@autovul/codeql-runner";
