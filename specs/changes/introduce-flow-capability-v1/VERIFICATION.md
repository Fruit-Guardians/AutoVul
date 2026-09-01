# Flow v1 requirement verification

- Status: Archived after verification on 2026-09-01
- Contract: `autovul.flow/1`
- Real matrix: 20 vulnerable/fixed fixtures across Python, JavaScript, Java and C/C++
- Portable evidence: `evidence/flow-v1-real-matrix/RESULTS.json`

`Covered` means the implementation and named deterministic check or real artifact
passed the final gate. The matrix evidence is required for real reproduction claims;
fake adapters are used only for failure and policy coverage.

| Requirement | Status | Evidence |
| --- | --- | --- |
| `REQ-FLOWV1-001` | Covered | Strict aggregate capability Schema and `test/research-architecture.test.ts`. |
| `REQ-FLOWV1-002` | Covered | `packages/contracts/src/research.ts` keeps the route separate from FlowModel. |
| `REQ-FLOWV1-003` | Covered | Static Application branches and `test/check-architecture.mjs`; no registry or base class. |
| `REQ-FLOWV1-004` | Covered | Architecture check and source inspection show no future-capability placeholder. |
| `REQ-FLOWV1-005` | Covered | Flow service uses shared status, cancellation, artifact, lock and replay services. |
| `REQ-FLOWV1-006` | Covered | Aggregate contracts return actions/hints only; Pi provider chooses every action in the real E2E. |
| `REQ-FLOWV1-007` | Covered | Core has no model port or retry loop; architecture check. |
| `REQ-FLOWV1-008` | Covered | Dependency and architecture checks prevent host/UI imports in Contracts and Core. |
| `REQ-FLOWV1-009` | Covered | Flow has one CodeQL adapter and adds no host or Capability claim. |
| `REQ-FLOWV1-010` | Covered | Pi real E2E invokes `autovul_research` validate and execute. |
| `REQ-FLOWV1-011` | Covered | Closed research action Schema and invalid-envelope tests. |
| `REQ-FLOWV1-012` | Covered | Side-effect-free validation test asserts no run, artifact or Analyzer call. |
| `REQ-FLOWV1-013` | Covered | Idempotent execute/resume test and one authoritative run artifact. |
| `REQ-FLOWV1-013A` | Covered | Idempotency-conflict test rejects a changed target without re-execution. |
| `REQ-FLOWV1-014` | Covered | Closed `autovul_run` Schema plus status/cancel/replay integration tests. |
| `REQ-FLOWV1-015` | Covered | Contract Schema and decision snapshots restrict envelope actions. |
| `REQ-FLOWV1-016` | Covered | Flow-specific actions occur only in revision-hint Schema/tests. |
| `REQ-FLOWV1-017` | Covered | Compact result snapshots contain only routing, decision, evidence and next-action fields. |
| `REQ-FLOWV1-018` | Covered | Contracts contain no Finding/report/WP or narrative recommendation field. |
| `REQ-FLOWV1-019` | Covered | Pi registration tests retain compatibility tools while prompts prefer the two aggregate entries. |
| `REQ-FLOWV1-020` | Covered | Literal Flow version and stable `model_id` Schema tests. |
| `REQ-FLOWV1-021` | Covered | FlowModel Schema/validation fixtures cover singular endpoints, steps and barriers. |
| `REQ-FLOWV1-022` | Covered | Language remains the previously accepted four-family set; real matrix is 5 cases per family. |
| `REQ-FLOWV1-023` | Covered | Closed `taint | value` Schema tests. |
| `REQ-FLOWV1-024` | Covered | Endpoint discriminant fixtures cover every accepted matcher kind. |
| `REQ-FLOWV1-025` | Covered | `test/m3-language-pack.test.ts` and compatibility projection retain selectors and locations. |
| `REQ-FLOWV1-026` | Covered | Directed step and barrier Schema/renderer tests. |
| `REQ-FLOWV1-027` | Covered | Strict FlowModel rejects execution, policy, evidence and presentation fields. |
| `REQ-FLOWV1-028` | Covered | Domain endpoint Schema is Analyzer-independent; architecture imports are checked. |
| `REQ-FLOWV1-029` | Covered | Strict singular fields and `additionalProperties: false`. |
| `REQ-FLOWV1-030` | Covered | Boundary accepts `unknown`; validator returns one model or bounded issues. |
| `REQ-FLOWV1-031` | Covered | Public export inspection and naming checks show no `FlowModelDraft`. |
| `REQ-FLOWV1-032` | Covered | Validation tests assert stable codes and JSON Pointer paths. |
| `REQ-FLOWV1-033` | Covered | Closed-set repair fixtures assert `allowed_values` and type fixtures assert `expected_kind`. |
| `REQ-FLOWV1-034` | Covered | Validation issue Schema has structured repair fields and no prose substitute. |
| `REQ-FLOWV1-035` | Covered | Invalid endpoint selectors, positions, ranges, discriminants and extra fields are rejected. |
| `REQ-FLOWV1-036` | Covered | Valid normalization snapshot returns only closed next actions. |
| `REQ-FLOWV1-037` | Covered | Invalid and validate-only tests assert no manifest, artifact or verification level. |
| `REQ-FLOWV1-038` | Covered | Pure validation snapshots and repeated-input tests are deterministic. |
| `REQ-FLOWV1-039` | Covered | Expectation Schema and mode validation enforce bounded vulnerable/fixed ranges. |
| `REQ-FLOWV1-040` | Covered | Execute envelope separates model, target, Analyzer, mode, expectation, budget and key; fingerprint tests cover TargetRef. |
| `REQ-FLOWV1-041` | Covered | Closed evidence-mode Schema. |
| `REQ-FLOWV1-042` | Covered | Mode excludes all Flow revision verbs. |
| `REQ-FLOWV1-043` | Covered | Probe policy tests require no expectation and cap evidence below reproduction. |
| `REQ-FLOWV1-044` | Covered | Reproduce validation requires vulnerable target/expectation only. |
| `REQ-FLOWV1-045` | Covered | Differential validation and 20 real cases require both targets and policies. |
| `REQ-FLOWV1-046` | Covered | Analyzer id is the closed literal `codeql`. |
| `REQ-FLOWV1-047` | Covered | Unavailable-Analyzer test blocks execute while pure validate remains usable. |
| `REQ-FLOWV1-048` | Covered | Database prerequisite, trusted-root and target-fingerprint tests return structured blocks. |
| `REQ-FLOWV1-049` | Covered | Preflight stays internal to execute; compatibility database tool remains separately registered. |
| `REQ-FLOWV1-050` | Covered | `FlowExecutionPort` returns observation only; port and architecture tests. |
| `REQ-FLOWV1-051` | Covered | Observation Schema separately records compile, endpoints, paths, gaps, refs and provenance. |
| `REQ-FLOWV1-052` | Covered | Decision matrix covers endpoint `observed`, `not_found` and `not_run` with bounded locations. |
| `REQ-FLOWV1-053` | Covered | Decision matrix covers path `observed`, `not_observed` and `not_run`. |
| `REQ-FLOWV1-054` | Covered | Projection/render failures become explicit capability gaps; unsupported-semantics tests. |
| `REQ-FLOWV1-055` | Covered | Adapter has no decision field; Core decision snapshots and real artifacts contain the verdict. |
| `REQ-FLOWV1-056` | Covered | One closed Flow decision object; contract snapshots contain no parallel status. |
| `REQ-FLOWV1-057` | Covered | Differential snapshots store fixed outcome/policy only inside `decision`. |
| `REQ-FLOWV1-058` | Covered | `test/flow-decision.test.ts` exhaustively maps normalized observations deterministically. |
| `REQ-FLOWV1-059` | Covered | Probe failure, timeout, unavailable prerequisite, cancellation and completed no-path tests remain distinct. |
| `REQ-FLOWV1-060` | Covered | Decision fixtures distinguish missing Source, missing Sink, endpoints-without-path and capability gap. |
| `REQ-FLOWV1-061` | Covered | Compact observation Schema/tests use stable codes and bounded refs/locations. |
| `REQ-FLOWV1-062` | Covered | Decision policy does not invent summary, barrier or context conclusions. |
| `REQ-FLOWV1-063` | Covered | No frontier observation is emitted without a trace evidence branch. |
| `REQ-FLOWV1-064` | Covered | Revision hint Schema requires action, JSON Pointer path, reason and structured constraints. |
| `REQ-FLOWV1-065` | Covered | Closed six-action revision-hint Schema and snapshots. |
| `REQ-FLOWV1-066` | Covered | Every emitted hint is tied to a compact observation/evidence ref and contains no model. |
| `REQ-FLOWV1-067` | Covered | Core returns hints but performs no revision or second execution. |
| `REQ-FLOWV1-068` | Covered | Real artifacts retain QL/SARIF while compact results expose bounded refs. |
| `REQ-FLOWV1-070` | Covered | Flow reuses the shared verification-level Schema and baseline meanings. |
| `REQ-FLOWV1-071` | Covered | Probe fixtures remain `generated` and never reproduce. |
| `REQ-FLOWV1-072` | Covered | Reproduced policy requires an observed vulnerable path; real cases satisfy it. |
| `REQ-FLOWV1-073` | Covered | Compile-only/no-path fixtures are capped at `compiled`. |
| `REQ-FLOWV1-074` | Covered | 20 real cases reach differential only with vulnerable flow and fixed no-flow. |
| `REQ-FLOWV1-075` | Covered | Fixed-policy-failure fixture prevents differential and preserves fixed decision data. |
| `REQ-FLOWV1-076` | Covered | Failure, block, cancel and timeout tests stay at committed evidence strength. |
| `REQ-FLOWV1-077` | Covered | Decision Policy never emits `variant_validated`. |
| `REQ-FLOWV1-078` | Covered | Fake tests are labeled policy coverage; only saved real CodeQL evidence supports the claim. |
| `REQ-FLOWV1-080` | Covered | Public `TaintQueryIntent` contracts and full baseline suite remain available. |
| `REQ-FLOWV1-081` | Covered | Compatibility round trips cover language, mode, selectors, locations, steps and sanitizers. |
| `REQ-FLOWV1-082` | Covered | Legacy self-edge projection has deterministic round-trip coverage. |
| `REQ-FLOWV1-083` | Covered | Compatibility context retains CWE/message/rationale; strict FlowModel excludes them. |
| `REQ-FLOWV1-084` | Covered | Lossy projections return a stable compatibility error. |
| `REQ-FLOWV1-085` | Covered | Legacy projection and aggregate decision tests share `decideFlow`. |
| `REQ-FLOWV1-086` | Covered | CLI/Pi compatibility tests and package checks pass unchanged. |
| `REQ-FLOWV1-087` | Covered | Existing pack/replay tests pass; the Flow rule-id repair restores a valid stable single-segment id. |
| `REQ-FLOWV1-088` | Covered | Strict probes, differential policy, real 20-case matrix and relocated replay all pass. |
| `REQ-FLOWV1-090` | Covered | Flow uses the shared manifest and committed research route, not a parallel state machine. |
| `REQ-FLOWV1-091` | Covered | Artifact Schema and saved matrix contain all required identity, observation, policy and evidence fields. |
| `REQ-FLOWV1-092` | Covered | Bundle-promotion failure/interruption tests prove evidence-before-authority ordering. |
| `REQ-FLOWV1-093` | Covered | Every real matrix case replays in a fresh Node process from a relocated runs root. |
| `REQ-FLOWV1-094` | Covered | Timeout, live cancel, idempotency, lock and recovery tests use shared services. |
| `REQ-FLOWV1-095` | Covered | Database runner relocation/trusted-root/fingerprint tests enforce canonical boundaries. |
| `REQ-FLOWV1-096` | Covered | Golden creates databases with build-mode none; Flow adapter invokes no target script. |
| `REQ-FLOWV1-097` | Covered | Schemas, budget, process output, locations, actions and concurrency are bounded. |
| `REQ-FLOWV1-098` | Covered | Output sanitizer tests and artifact inspection show no prompt, environment dump or credential. |
| `REQ-FLOWV1-099` | Covered | Core performs no automatic retry; semantic mismatch and invalid input require host action. |

## Real Analyzer gate

`test:flow-golden-real` passed all 20 cases with CodeQL 2.26.1 and adapter
`autovul.codeql-flow/1`. Each case recorded a vulnerable `connected` outcome,
fixed `no_path`, `differential`, fixture tree hashes, portable database
fingerprints, QL/SARIF hashes, and an identical replay from a fresh process with
a relocated runs root.

`test:flow-pi-e2e` passed the aggregate Pi sequence:
`autovul_research(validate) -> autovul_research(execute) -> autovul_run(replay)`
and observed the terminal Flow/differential UI state.

## Final command gate

Passed on 2026-09-01:

```text
npm run lint
npm test                         # 28 files, 165 tests
npm run pack:check               # 5 package outputs clean
npm run test:flow-golden-real    # 20/20 real differential + relocated replay
npm run test:flow-pi-e2e         # aggregate Flow validate/execute/replay + UI
npm run test:m4-pi-e2e           # compatibility Pi chain + relocated Query Pack
```

The compatibility Pi diagnostic initially stopped in its test harness because
`test/m4-pi-rpc-real.mjs` omitted the `node:child_process` import. After adding
the missing import, the unchanged real CodeQL compatibility scenario passed.

No requirement mapping is pending. Stable behavior is merged into root
`SPEC.md` v1.4; this change is Archived.
