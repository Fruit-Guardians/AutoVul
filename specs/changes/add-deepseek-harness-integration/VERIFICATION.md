# DeepSeek Harness Integration Requirement Verification

- Status: Implemented & Verified
- Public contract: `v2.contracts/1`
- Host integration package: `@autovul/deepseek-harness`
- Acceptance evidence:
  - `specs/changes/add-deepseek-harness-integration/evidence/acceptance-transcript.json`
- Verification suite:
  - `test/check-dependencies.mjs`
  - `test/deepseek-harness.test.ts`
  - `test/deepseek-harness-acceptance.test.ts`

`Covered` means the requirement is verified by deterministic automated tests, architectural boundaries check, and an end-to-end function calling acceptance fixture on production application adapters without fake mocks or bypassed validation.

| Requirement | Status | Evidence |
| --- | --- | --- |
| `REQ-DSEEK-001` | Covered | `@autovul/deepseek-harness` declared dependencies restricted to `@autovul/contracts`, `@autovul/core`, and `@autovul/codeql-runner`; verified by `test/check-dependencies.mjs`. |
| `REQ-DSEEK-002` | Covered | `createDeepSeekHarnessPlugin` exposes `autovul_research` with input parameter schemas conforming to `AutovulResearchToolInputSchema`; verified by `test/deepseek-harness.test.ts` and `test/deepseek-harness-acceptance.test.ts`. |
| `REQ-DSEEK-003` | Covered | `createDeepSeekHarnessPlugin` exposes `autovul_run` with input parameter schemas conforming to `AutovulRunToolInputSchema`; verified by `test/deepseek-harness.test.ts` and `test/deepseek-harness-acceptance.test.ts`. |
| `REQ-DSEEK-004` | Covered | Tool definitions emitted strictly in function-calling format (`{ type: "function", function: { name, description, parameters } }`); verified by `test/deepseek-harness.test.ts`. |
| `REQ-DSEEK-005` | Covered | Tool invocations route exclusively through `ApplicationApi.research()` and `ApplicationApi.manageRun()`; verified by `test/deepseek-harness.test.ts` and `test/deepseek-harness-acceptance.test.ts`. |
| `REQ-DSEEK-006` | Covered | Adapter catches domain errors and normalizes them into structured failure outputs (`{ success: false, output, error }`) without unhandled exceptions; verified by `test/deepseek-harness.test.ts` and `test/deepseek-harness-acceptance.test.ts`. |
| `REQ-DSEEK-007` | Covered | System prompt instructions provide clear guidance on native-audit-first, capability selection (flow, missing_check, typestate, change_observation, variant_search), and playbooks; verified by `test/deepseek-harness.test.ts` and `test/playbooks.test.ts`. |
| `REQ-DSEEK-008` | Covered | Calling `plugin.close()` cleanly delegates to `ApplicationApi.close()` and transitions application state; subsequent tool calls cleanly return structured `INVALID_STATE_TRANSITION` errors; verified by `test/deepseek-harness.test.ts` and `test/deepseek-harness-acceptance.test.ts`. |
| `REQ-DSEEK-009` | Covered | Real boundary acceptance test (`test/deepseek-harness-acceptance.test.ts`) emulates the complete OpenAI/DeepSeek function calling protocol against production plugin and real `createLocalApplication` with real Git repositories; covers differential missing_check, status query, replay, invalid input, cancellation, and clean shutdown; generates immutable transcript at `specs/changes/add-deepseek-harness-integration/evidence/acceptance-transcript.json`. |

## Verification Command Gate

Passed:

```bash
npm run build
npm run typecheck
npm test
npm run lint
npm run pack:check
```
