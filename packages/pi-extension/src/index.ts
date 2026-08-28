import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createLocalApplication, readAutovulEnv } from "@autovul/codeql-runner";

import { registerCommands } from "./commands.js";
import { registerLifecycle } from "./lifecycle.js";
import { registerTools } from "./tools.js";
import type { PiUiState } from "./types.js";

/** Pi integration composition root: assemble the Application and register adapters. */
export default function autovulExtension(pi: ExtensionAPI): void {
  const applicationOptions = { cwd: process.cwd(), timeoutMs: configuredTimeoutMs() };
  const runsDir = readAutovulEnv("RUNS_DIR");
  const application = runsDir === undefined
    ? createLocalApplication(applicationOptions)
    : createLocalApplication({ ...applicationOptions, runsDir });
  const state: PiUiState = { status: "ready", phase: "idle", diagnostics: [] };
  let closePromise: Promise<void> | undefined;
  const closeApplication = (): Promise<void> => {
    closePromise ??= application.close();
    return closePromise;
  };

  registerLifecycle(pi, application, state, closeApplication);
  registerCommands(pi, application, state);
  registerTools(pi, application);
}

function configuredTimeoutMs(): number {
  const parsed = Number.parseInt(readAutovulEnv("TIMEOUT_MS") ?? "120000", 10);
  return Number.isFinite(parsed) && parsed >= 1_000 ? Math.min(parsed, 600_000) : 120_000;
}
