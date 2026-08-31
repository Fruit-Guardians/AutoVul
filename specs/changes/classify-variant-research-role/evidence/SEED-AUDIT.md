# Variant seed availability audit

Status: one Variant-eligible seed artifact is available at a temporary,
path-dependent artifact root; no second family is available.

## Reviewed candidate: MissingCheck OpenClaw CVE-2026-43572

The MissingCheck v1 SPEC is `Verified` for its frozen JavaScript single-file CFG
boundary. Its real Golden creates a normal AutoVul run, obtains a `differential`
result, and replays that run in a new process. The admission evidence also records
the immutable OpenClaw revisions, CodeQL provenance, query digest, and the
vulnerable/fixed witness counts.

The checked-in admission `RESULTS.json` is only a provenance record with status
`admission_evidence_only`; it is not itself a seed. However, the real Golden’s
committed run artifact is still present in its temporary runtime root:

- run id `run_6693d7700e7bb717`;
- capability `missing_check`, contract `autovul.missing-check/1`;
- status `completed`, verification level `differential`;
- normalized hypothesis, target database paths, CodeQL provenance, observation,
  decision, and SARIF evidence; and
- result artifact reference `research/missing-check/result.json`.

On 2026-08-30, a fresh Application instance configured with that exact runtime
root replayed the run and returned the same `missing_check` `check_missing` /
fixed `check_present` differential decision. It satisfies `REQ-VARIANT-002`
while its paths, target databases, and analyzer remain available.

The run is temporary rather than portable: its artifact and target paths are
under a temporary directory. It MUST be treated as an explicit external replay
dependency and MUST NOT be copied into this repository or advertised as a
durable user artifact without a retention/privacy decision.

## Required next evidence

Before a Variant result or service is treated as durable, its seed artifact MUST
be retained under the project’s normal artifact policy and record all of:

- the run id and `missing_check` contract version;
- `reproduced` or stronger verification level;
- immutable target fingerprints and CodeQL provenance;
- normalized hypothesis, observation, decision, and replay inputs; and
- a model-free replay result against the retained artifact.

The artifact must be retained without broadening the frozen MissingCheck scope.
The current temporary run may support bounded classification research only; a
second independently verified family is still required by `REQ-VARIANT-001`.

## Current disposition

Variant is no longer blocked at its first-seed admission, but remains blocked on
the two-family corpus, safe/lower-similarity members, strategy spike, and owning
Capability validation requirements. No `variant_validated` claim is authorized.
