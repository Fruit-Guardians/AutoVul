import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { ApplicationApi } from "@autovul/core";

import { CODEQL_DISCOVERY_HINT } from "./prompts.js";
import type { PiUiState } from "./types.js";
import { absorbDetails, hideWidget, readCandidate, renderFooter, renderUi, toolLabel, toolPhase } from "./ui.js";

export function registerLifecycle(
  pi: ExtensionAPI,
  _application: ApplicationApi,
  state: PiUiState,
  closeApplication: () => Promise<void>,
): void {
  process.once("beforeExit", () => {
    void closeApplication();
  });
  process.once("SIGINT", () => {
    void closeApplication().finally(() => process.exit(130));
  });
  process.once("SIGTERM", () => {
    void closeApplication().finally(() => process.exit(143));
  });

  pi.on("session_start", async (_event, ctx) => {
    renderFooter(ctx, state);
    hideWidget(ctx);
  });
  pi.on("before_agent_start", async (event) => {
    if (event.prompt.includes("Use AutoVul M4 inside the host Pi Agent Loop.") || event.prompt.includes("Use AutoVul M3 inside the host Pi Agent Loop.")) return undefined;
    return { systemPrompt: `${event.systemPrompt}\n\n${CODEQL_DISCOVERY_HINT}` };
  });
  pi.on("tool_execution_start", async (event, ctx) => {
    if (!isAutovulTool(event.toolName)) return;
    delete state.capability;
    delete state.decisionOutcome;
    delete state.operationStatus;
    delete state.artifactRef;
    delete state.revisionHintCount;
    state.diagnostics = [];
    state.status = "running";
    state.phase = toolPhase(event.toolName, event.args);
    const candidate = readCandidate(event.args);
    if (candidate?.round !== undefined) state.round = candidate.round;
    if (ctx.hasUI) ctx.ui.setWorkingMessage(`AutoVul · ${toolLabel(event.toolName)}…`);
    renderUi(ctx, state);
  });
  pi.on("tool_result", async (event, ctx) => {
    if (!isAutovulTool(event.toolName)) return;
    if (event.isError) {
      state.status = "failed";
      state.diagnostics = ["TOOL_ERROR"];
    } else {
      absorbDetails(state, event.details);
    }
    if (ctx.hasUI) ctx.ui.setWorkingMessage();
    renderUi(ctx, state);
  });
  pi.on("agent_settled", async (_event, ctx) => {
    if (ctx.hasUI) ctx.ui.setWorkingMessage();
    renderFooter(ctx, state);
    hideWidget(ctx);
  });
  pi.on("session_shutdown", async () => closeApplication());
}

function isAutovulTool(toolName: string): boolean {
  return toolName === "autovul_research" || toolName === "autovul_run" || toolName === "codeql_database" || toolName === "codeql_workflow" || toolName === "codeql_query";
}
