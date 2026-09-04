# @autovul/pi-extension

`@autovul/pi-extension` provides a thin integration adapter for **Pi Agent**.

## Host Boundary

- **Pi Agent** owns the Agent loop, conversation context, LLM access, reasoning, and user approval.
- **Native audit first**: Pi may inspect code and deliver a semantic audit conclusion without calling AutoVul. The tools are optional escalation points, and CodeQL is not a prerequisite.
- **AutoVul Extension** registers domain tools, maps inputs to `ApplicationApi`, and renders compact execution widgets.
- **Zero Agent-in-Agent**: The extension never launches an internal agent loop or autonomous retry prompt.

## Registered Tools

- `autovul_research`: Validates or executes a versioned Flow, MissingCheck, or Typestate hypothesis, or executes an Analyzer Service request. Change Observation is archived; Variant Search remains an accepted, in-progress branch.
- `autovul_run`: Manages long-running or completed runs: `status`, `cancel`, or `replay`.
- Legacy compatibility tools: `codeql_database`, `codeql_workflow`, `codeql_query`.

## Slash Commands & UI

- `/codeql`: Show extension status and diagnostic summary.
- `/codeql doctor`: Verify CodeQL CLI availability and language packs.
- `/codeql-status [run-id]`: View current run state and phase.
- `/codeql-generate`: Initiates a query synthesis workflow.
