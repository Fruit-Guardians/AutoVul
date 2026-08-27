import type { AgentToolResult, ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
  asDomainError,
  CodeqlDatabaseToolInputSchema,
  CodeqlQueryToolInputSchema,
  CodeqlWorkflowToolInputSchema,
  DomainError,
  parseSchema,
  type DatabaseResult,
  type DoctorResult,
  type ProbeEvidence,
  type QueryDraftReport,
  type QueryPackManifest,
  type QueryVerification,
  type QueryWorkflowStatus,
} from "@pure-auto-codeql/contracts";
import type { ApplicationApi } from "@pure-auto-codeql/core";

import type { ToolDetails } from "./types.js";

export function registerTools(pi: ExtensionAPI, application: ApplicationApi): void {
  pi.registerTool({
    name: "codeql_database",
    label: "CodeQL database",
    description: "Read-only CodeQL doctor, database inspect, or database validate operation.",
    promptSnippet: "Read-only CodeQL environment/database inspection",
    parameters: CodeqlDatabaseToolInputSchema,
    execute: async (_toolCallId: string, rawParams: unknown, signal: AbortSignal | undefined, _onUpdate: unknown, _ctx: ExtensionContext): Promise<AgentToolResult<ToolDetails>> => {
      try {
        const params = parseSchema(CodeqlDatabaseToolInputSchema, rawParams, "codeql_database input");
        return toolSuccess(await executeDatabaseAction(application, params.action, params.path, signal));
      } catch (error: unknown) {
        throw asDomainError(error);
      }
    },
  });

  pi.registerTool({
    name: "codeql_workflow",
    label: "CodeQL workflow",
    description: "Start, inspect, or finalize the persisted multi-language CodeQL query workflow.",
    promptSnippet: "Persisted multi-language CodeQL query workflow",
    parameters: CodeqlWorkflowToolInputSchema,
    execute: async (_toolCallId: string, rawParams: unknown, signal: AbortSignal | undefined, _onUpdate: unknown, _ctx: ExtensionContext): Promise<AgentToolResult<ToolDetails>> => {
      try {
        const params = parseSchema(CodeqlWorkflowToolInputSchema, rawParams, "codeql_workflow input");
        if (params.action === "start") {
          if (params.spec === undefined) throw new DomainError("INVALID_INPUT", "input", "workflow start requires spec", false);
          return toolSuccess(await application.workflowStart(params.spec, signal === undefined ? {} : { signal }));
        }
        if (params.run_id === undefined) throw new DomainError("INVALID_INPUT", "input", `workflow ${params.action} requires run_id`, false, { action: params.action });
        return params.action === "status"
          ? toolSuccess(await application.workflowStatus(params.run_id))
          : toolSuccess(await application.workflowFinalize(params.run_id, signal === undefined ? {} : { signal }));
      } catch (error: unknown) {
        throw asDomainError(error);
      }
    },
  });

  pi.registerTool({
    name: "codeql_query",
    label: "CodeQL query",
    description: "Probe, LSP-draft, compile, execute, and differential-verify a structured multi-language CodeQL candidate.",
    promptSnippet: "Probe or LSP-draft a candidate, then verify it with authoritative CodeQL CLI",
    parameters: CodeqlQueryToolInputSchema,
    execute: async (_toolCallId: string, rawParams: unknown, signal: AbortSignal | undefined, _onUpdate: unknown, _ctx: ExtensionContext): Promise<AgentToolResult<ToolDetails>> => {
      try {
        const params = parseSchema(CodeqlQueryToolInputSchema, rawParams, "codeql_query input");
        if (params.action === "probe") {
          if (params.intent === undefined) throw new DomainError("INVALID_INPUT", "input", "codeql_query probe requires intent", false);
          return toolSuccess(await application.queryProbe(params.run_id, params.intent, signal === undefined ? {} : { signal }));
        }
        if (params.action === "draft") {
          if (params.candidate === undefined) throw new DomainError("INVALID_INPUT", "input", "codeql_query draft requires candidate", false);
          return toolSuccess(await application.queryDraft(params.run_id, params.candidate, signal === undefined ? {} : { signal }));
        }
        if (params.candidate === undefined) throw new DomainError("INVALID_INPUT", "input", "codeql_query verify requires candidate", false);
        return toolSuccess(await application.queryVerify(params.run_id, params.candidate, signal === undefined ? {} : { signal }));
      } catch (error: unknown) {
        throw asDomainError(error);
      }
    },
  });
}

async function executeDatabaseAction(application: ApplicationApi, action: "doctor" | "inspect" | "validate", path: string | undefined, signal: AbortSignal | undefined): Promise<DoctorResult | DatabaseResult> {
  if (action === "doctor") return application.doctor(signal === undefined ? {} : { signal });
  if (path === undefined) throw new DomainError("INVALID_INPUT", "input", `The ${action} action requires path`, false, { action });
  return action === "inspect" ? application.databaseInspect(path, signal === undefined ? {} : { signal }) : application.databaseValidate(path, signal === undefined ? {} : { signal });
}

function toolSuccess(details: ToolDetails): AgentToolResult<ToolDetails> {
  return {
    content: [{ type: "text", text: JSON.stringify({ ok: true, result: details }, null, 2) }],
    details,
  };
}
