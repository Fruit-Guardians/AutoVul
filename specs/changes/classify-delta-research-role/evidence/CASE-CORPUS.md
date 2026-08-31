# Delta Classification Case Corpus

Status: classification evidence complete; the primary role `analyzer_service`
was explicitly accepted with no production implementation authorized.

This corpus records only immutable revision facts and bounded scopes. It does
not introduce a Delta contract, decision, result, or product support claim.

## D-001 — MissingCheck owning-Capability target differential

- Proposed owner: MissingCheck.
- Input shape: one MissingCheck hypothesis, a vulnerable CodeQL database, a fixed
  CodeQL database, and MissingCheck-owned operation/check expectations.
- Claimed Delta role: `existing_mode`.
- Provenance: OpenClaw CVE-2026-43572, MIT; immutable vulnerable commit
  `75b4c059b8405dfbd50884b773346a9946fabd20` and fixed commit
  `80b1fa17bfc3f6a668492f0326ea52f48bb89776`, scoped to
  `extensions/msteams/src/monitor-handler.ts`.
- Required observation: MissingCheck's own protected-operation, required-check,
  and local-CFG relation observations on both targets; MissingCheck's own
  fixed-side policy decides the result.
- Why it is discriminating: even when a vulnerable/fixed comparison is useful,
  it has no independent change hypothesis or verdict. Moving it to Delta would
  duplicate `mode: differential` and separate evidence from the MissingCheck
  predicate.
- Observed evidence: the production CodeQL JavaScript adapter produced one
  persisted unchecked witness on the vulnerable target, a checked fixed target,
  an authoritative `differential` result, and identical fresh-process replay.
  The Golden stages only the selected source file and executes no target install,
  build, or test scripts.
- Counter-example: a line diff that mentions authorization but produces no
  MissingCheck-owned relation change cannot change the MissingCheck decision.
- Replay dependencies: the committed MissingCheck artifact, target database
  fingerprints, `autovul.missing-check/1`, and CodeQL provenance.

## D-002 — OpenClaw sender-authorization patch facts

- Repository: `https://github.com/openclaw/openclaw.git` (MIT).
- Base: `75b4c059b8405dfbd50884b773346a9946fabd20`.
- Head: `80b1fa17bfc3f6a668492f0326ea52f48bb89776`.
- Scope: `extensions/msteams/src/monitor-handler.ts`.
- Required deterministic facts: the head adds an
  `isSigninInvokeAuthorized` call before the direct
  `handleSigninTokenExchangeInvoke` operation; the bounded CodeQL witness in
  the MissingCheck admission evidence changes from one unchecked witness to
  zero.
- Candidate role: `analyzer_service` for the Git/AST facts; the security
  predicate remains MissingCheck-owned.
- Rejected role for this operation: `research_capability`. The patch facts do
  not themselves decide `check_missing` or `check_present`; that decision is
  defined by the selected operation/check/relation hypothesis.
- Counter-example: the same revision includes changelog and test changes. A
  deterministic diff can report those facts but cannot infer their security
  relevance.
- Replay dependencies: immutable revisions, path filter, a no-build
  JavaScript AST/CFG analyzer, and the MissingCheck evidence query.

## D-003 — kohya_ss shell invocation patch facts

- Repository: `https://github.com/bmaltais/kohya_ss.git` (Apache-2.0).
- Base: `8633484a5a5aebe17c805bb3b46760873ed1f09b`.
- Head: `831af8babeb75faff62bcc6a8c6a4f80354f1ff1`.
- Scope: `kohya_gui/basic_caption_gui.py`.
- Observed deterministic facts: the immutable raw patch object replaces
  `subprocess.run(run_cmd, shell=True, env=env)` with
  `subprocess.run(run_cmd, env=env)` at the scoped call site. The observation
  source is the public raw patch, reproducible with
  `git diff --no-ext-diff <base> <head> -- kohya_gui/basic_caption_gui.py`.
- Claimed security-property context: the repository’s existing Golden-case
  metadata identifies this revision pair as the fixed side of GHSL-2024-019 /
  CVE-2024-32022. That provenance selects a Flow research question; it is not
  evidence that the patch fact itself proves a Flow result.
- Candidate role: `analyzer_service` for a bounded call-argument change fact.
- Rejected role for this operation: `research_capability`. The absence of one
  argument in a patch cannot decide source reachability, shell interpretation,
  exploitability, or Flow verification.
- Counter-example: the same commit changes 18 files. A bounded observer must
  return the scoped call-argument fact and preserve the remaining raw patch only
  as artifact evidence; it must not label every changed call site fixed.
- Replay dependencies: immutable revisions, path filter, and a Git object diff
  parser. No target code, build, install, or test script is executed.

## Preliminary matrix

| Case | What changes the next host action | Artifact-only facts | Provisional role |
| --- | --- | --- | --- |
| D-001 | Run/revise the owning MissingCheck hypothesis | target diff internals | `existing_mode` |
| D-002 | Revise/run the owning MissingCheck hypothesis | file hunks, test/changelog edits | `analyzer_service` candidate |
| D-003 | Revise/run the owning Flow hypothesis when Flow work resumes | remaining 17-file patch and advisory prose | `analyzer_service` candidate |

## Classification conclusion

The primary role is `analyzer_service`: D-002 and D-003 require bounded,
deterministic revision facts before another Capability can be selected or revised,
but neither supplies an independent security success predicate. D-001 is instead
the existing `differential` mode owned by MissingCheck. `research_capability` is
rejected: no case has an independent hypothesis, decision, revision policy, and
real verification gate. `host_strategy` is rejected as the primary role because
the bounded facts themselves are deterministic and reusable, though commit choice
and security interpretation remain host work. `reject` is rejected because the
bounded patch observations do change the next Capability action.

This conclusion does not declare that a public change-observation service is worth
implementing. Per the parent SPEC, implementation requires a separate accepted
follow-up SPEC before any production contract or module is introduced.
