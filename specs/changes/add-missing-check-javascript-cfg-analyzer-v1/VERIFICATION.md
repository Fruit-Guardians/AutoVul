# MissingCheck JavaScript CFG Analyzer v1 Requirement Verification

- Status: Implemented & Verified
- Public contract: `v2.contracts/1`, `autovul.missing-check/1`
- Supported target: `GitRevisionTargetPairSchema` (`kind: "git_revision"`)
- Verified language scope: JavaScript AST intra-procedural CFG (TypeScript syntax parser utilized, semantics restricted to JavaScript)
- Real vulnerability case: OpenClaw MSTeams Token Exchange (CVE-2026-43572, MIT)
- Verification suite:
  - `test/missing-check-javascript-cfg.test.ts`
  - `test/variant-search-family-verification.test.ts`

`Covered` means the requirement is verified by deterministic automated tests, real Git commit inspection, AST parsing, and dominance CFG evaluation without fake runner fallback or bypassed boundaries.

| Requirement | Status | Evidence |
| --- | --- | --- |
| `REQ-MCHECK-JS-001` | Covered | `MissingCheckResearchToolInputSchema` pairs `analyzer_id: "javascript_cfg"` with immutable `GitRevisionTargetPairSchema`; invalid targets rejected; `test/missing-check-javascript-cfg.test.ts`. |
| `REQ-MCHECK-JS-002` | Covered | Request and analyzer provenance schemas admit `analyzer_id: "javascript_cfg"` alongside `"codeql"`; `test/missing-check-javascript-cfg.test.ts`. |
| `REQ-MCHECK-JS-003` | Covered | `JavascriptCfgMissingCheckAdapter` reads JavaScript source directly from Git object database within canonicalized `trustedRoots` via `git cat-file -p` without CodeQL CLI; `test/missing-check-javascript-cfg.test.ts`. |
| `REQ-MCHECK-JS-004` | Covered | Emits `evidence_kind: "real_analyzer"` with authoritative AST/CFG locations and evidence references (`missing-check/{hypothesis_id}/{revision}/witnesses.json`); `test/missing-check-javascript-cfg.test.ts`. |
| `REQ-MCHECK-JS-005` | Covered | Evaluates condition polarity (`check()` vs `!check()`), reporting `checked_witness` when check dominates all paths and `unchecked_witness` when an unhedged path exists; unsupported loops, switches, try-blocks, with-statements, jumps, conditional/short-circuit expressions with calls, statement depth (>250), and path breadth (>64) return `incomplete` with structured gaps; `test/missing-check-javascript-cfg.test.ts`. |
| `REQ-MCHECK-JS-006` | Covered | In `mode: "differential"`, analyzes both vulnerable and fixed Git revisions and reaches real `differential` verification level on OpenClaw CVE-2026-43572; `test/missing-check-javascript-cfg.test.ts`, `test/variant-search-family-verification.test.ts`. |
| `REQ-MCHECK-JS-007` | Covered | Replay executes in isolated workspace namespace (`missing-check-replay/`), verifies Git commit fingerprints, and asserts SHA-256 evidence immutability of the original run; mutated evidence and diverging fingerprints are detected and fail replay; `test/missing-check-javascript-cfg.test.ts`. |

## Verification Command Gate

Passed:

```bash
npm run build
npm run typecheck
npm test
npm run lint
npm run pack:check
```
