# AutoVul V2 instructions

Read and follow @../AGENTS.md. That file is the authoritative project charter.

Read @../SPEC.md before changing behavior. Material changes to contracts, workflows, artifacts, security boundaries, analyzers or host integrations require an accepted change SPEC under `specs/changes/` before implementation.

AutoVul is not an Agent and not a general Agent Harness. It is a host-independent vulnerability-research capability layer used through Pi Agent, DeepSeek Harness, MCP, CLI and future thin integrations.

- The host owns models, the Agent Loop, context, planning, generic tools and user interaction.
- This project owns vulnerability semantics, deterministic analyzer execution, evidence, validation, budgets and replayable artifacts.
- Preserve the dependency direction `contracts <- core <- analyzers/runners <- integrations`.
- Never present model output, compile-only results, mocks or failed verification as a confirmed vulnerability.
- Keep changes focused, preserve user work and run the smallest relevant validation.
