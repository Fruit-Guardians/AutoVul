import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import {
  asDomainError,
  DomainError,
  type DatabaseResult,
  type DoctorResult,
  type RunManifest,
} from "@pure-auto-codeql/contracts";
import type { ApplicationApi } from "@pure-auto-codeql/core";

import { generationPrompt } from "./prompts.js";
import type { PiUiState } from "./types.js";
import { absorbDetails, formatCommandResult, hideWidget, renderFooter } from "./ui.js";

export function registerCommands(pi: ExtensionAPI, application: ApplicationApi, state: PiUiState): void {
  pi.registerCommand("codeql", {
    description: "Show PureAutoCodeQL help, doctor, or persisted status",
    handler: async (args: string, ctx: ExtensionCommandContext) => {
      const tokens = args.trim().split(/\s+/).filter(Boolean);
      const action = tokens[0] ?? "help";
      if (action === "doctor") {
        await showResult(ctx, state, "doctor", tokens.includes("--json"), () => application.doctor());
        return;
      }
      if (action === "status") {
        await showStatus(ctx, state, application, tokens.filter((token) => token !== "--json")[1], tokens.includes("--json"));
        return;
      }
      if (action === "generate") {
        await sendGeneratePrompt(pi, ctx, tokens.slice(1).join(" "));
        return;
      }
      if (action !== "help") ctx.ui.notify(`Unknown /codeql action: ${action}. Use /codeql for help.`, "warning");
      showHelp(ctx);
      renderFooter(ctx, state);
      hideWidget(ctx);
    },
  });

  pi.registerCommand("codeql-generate", {
    description: "Force-start M3 from a natural-language vulnerability description",
    handler: async (args: string, ctx: ExtensionCommandContext) => sendGeneratePrompt(pi, ctx, args.trim()),
  });
  pi.registerCommand("codeql-doctor", {
    description: "Check the local CodeQL CLI and available extractors",
    handler: async (args: string, ctx: ExtensionCommandContext) => showResult(ctx, state, "doctor", args.trim() === "--json", () => application.doctor()),
  });
  pi.registerCommand("codeql-status", {
    description: "Show a persisted V2 run manifest",
    handler: async (args: string, ctx: ExtensionCommandContext) => {
      const tokens = args.trim().split(/\s+/).filter(Boolean);
      await showStatus(ctx, state, application, tokens.find((token) => token !== "--json"), tokens.includes("--json"));
    },
  });
}

async function showStatus(ctx: ExtensionCommandContext, state: PiUiState, application: ApplicationApi, requestedRunId?: string, json = false): Promise<void> {
  const runId = requestedRunId ?? state.runId;
  if (runId === undefined) {
    ctx.ui.notify("No CodeQL run is known in this Pi session. Use /codeql-generate or /codeql-status <run-id>.", "info");
    renderFooter(ctx, state);
    hideWidget(ctx);
    return;
  }
  await showResult(ctx, state, "status", json, () => application.status(runId));
}

async function showResult(ctx: ExtensionCommandContext, state: PiUiState, toolName: string, json: boolean, operation: () => Promise<DoctorResult | DatabaseResult | RunManifest>): Promise<void> {
  try {
    const result = await operation();
    absorbDetails(state, result);
    renderFooter(ctx, state);
    hideWidget(ctx);
    ctx.ui.notify(json ? JSON.stringify({ ok: true, result }, null, 2) : formatCommandResult(toolName, result), "info");
  } catch (error: unknown) {
    const domainError = asDomainError(error);
    state.status = "failed";
    state.diagnostics = [domainError.code];
    renderFooter(ctx, state);
    hideWidget(ctx);
    ctx.ui.notify(json ? JSON.stringify({ ok: false, error: domainError.toRecord() }, null, 2) : `CodeQL ✗ ${domainError.code}: ${domainError.message}`, "error");
  }
}

async function sendGeneratePrompt(pi: ExtensionAPI, ctx: ExtensionCommandContext, args: string): Promise<void> {
  let request = args;
  if (request.length === 0 && ctx.hasUI) {
    request = (await ctx.ui.editor("PureAutoCodeQL · Describe the vulnerability and database paths", "Project source root:\nVulnerable database:\nFixed database (optional):\n\nVulnerability description or patch:\n"))?.trim() ?? "";
  }
  if (request.length === 0) {
    ctx.ui.notify("Cancelled. Use /codeql-generate <vulnerability description> or type the request directly.", "info");
    return;
  }
  if (!ctx.isIdle()) {
    ctx.ui.notify("Pi is busy. Wait for the current turn to finish before starting another CodeQL workflow.", "warning");
    return;
  }
  pi.sendUserMessage(generationPrompt(ctx.cwd, request));
}

function showHelp(ctx: ExtensionCommandContext): void {
  ctx.ui.notify([
    "PureAutoCodeQL native Pi workflow",
    "Normal CodeQL/vulnerability requests are handled automatically by the host Pi Agent Loop.",
    "/codeql-generate [description]  force-start M4; opens an editor when omitted",
    "/codeql doctor                  inspect CodeQL CLI and extractors",
    "/codeql-status [run-id]          show the current or specified run",
    "The footer shows the current phase; a small widget appears only while work is active or a pack is ready.",
  ].join("\n"), "info");
}
