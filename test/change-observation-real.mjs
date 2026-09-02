import assert from "node:assert/strict";

import { createLocalApplication } from "@autovul/codeql-runner";

const OPENCLAW_BASE = "75b4c059b8405dfbd50884b773346a9946fabd20";
const OPENCLAW_HEAD = "80b1fa17bfc3f6a668492f0326ea52f48bb89776";
const GHOST_BASE = "a8bea3a4ceec4c852b880f4885119453c3d8588e";
const GHOST_HEAD = "6b1c85c30dd0bacb4d5ffe64fc675ac9342d800c";

if (process.env.AUTOVUL_RUN_REAL !== "1") {
  console.log(JSON.stringify({ status: "SKIPPED", reason: "set AUTOVUL_RUN_REAL=1 with local immutable Git repositories" }));
  process.exit(0);
}

const openclawRepository = required("AUTOVUL_CHANGEOBS_OPENCLAW_REPOSITORY");
const ghostRepository = required("AUTOVUL_CHANGEOBS_GHOST_REPOSITORY");
const workspaceRoot = required("AUTOVUL_CHANGEOBS_WORKSPACE_ROOT");
const runsDir = required("AUTOVUL_CHANGEOBS_RUNS_DIR");
const mode = process.env.AUTOVUL_CHANGEOBS_MODE ?? "execute";
const app = createLocalApplication({ workspaceRoot, runsDir, timeoutMs: 300_000 });

try {
  if (mode === "execute") {
    const openclaw = await app.research(request(openclawRepository, OPENCLAW_BASE, OPENCLAW_HEAD, "extensions/msteams/src/monitor-handler.ts"));
    const ghost = await app.research(request(ghostRepository, GHOST_BASE, GHOST_HEAD, "ghost/core/core/server/services/auth/session/session-service.js"));
    assertCompleted(openclaw, "OpenClaw");
    assertCompleted(ghost, "Ghost");
    assert(openclaw.observation.event_changes.some((event) => event.event_kind === "direct_call_added" && event.selector.join(".") === "isSigninInvokeAuthorized"), "OpenClaw did not record the added authorization call");
    assert(ghost.observation.event_changes.some((event) => event.event_kind === "direct_call_added" && event.selector.join(".") === "req.session.regenerate"), "Ghost did not record the added session regeneration call");
    assertNoCapabilityVerdict(openclaw);
    assertNoCapabilityVerdict(ghost);
    console.log(JSON.stringify({
      status: "PASS",
      mode,
      openclaw: summary(openclaw),
      ghost: summary(ghost),
    }));
  } else if (mode === "replay") {
    const openclawRunId = required("AUTOVUL_CHANGEOBS_OPENCLAW_RUN_ID");
    const ghostRunId = required("AUTOVUL_CHANGEOBS_GHOST_RUN_ID");
    const openclaw = await app.manageRun({ action: "replay", run_id: openclawRunId });
    const ghost = await app.manageRun({ action: "replay", run_id: ghostRunId });
    assert.deepEqual({ service: openclaw.service, status: openclaw.status }, { service: "change_observation", status: "match" });
    assert.deepEqual({ service: ghost.service, status: ghost.status }, { service: "change_observation", status: "match" });
    console.log(JSON.stringify({
      status: "PASS",
      mode,
      openclaw: replaySummary(openclaw),
      ghost: replaySummary(ghost),
    }));
  } else {
    throw new Error(`Unsupported AUTOVUL_CHANGEOBS_MODE: ${mode}`);
  }
} finally {
  await app.close();
}

function request(repository, base_revision, head_revision, pathFilter) {
  return {
    action: "execute",
    service: "change_observation",
    service_version: "autovul.change-observation/1",
    input: {
      repository: { kind: "trusted_local_git_repository", path: repository },
      base_revision,
      head_revision,
      path_filters: [pathFilter],
    },
  };
}

function assertCompleted(result, label) {
  assert.equal(result.service, "change_observation", `${label} result did not select the Analyzer Service route`);
  assert.equal(result.operation_status, "completed", `${label} observation did not complete`);
  assert.ok(result.observation, `${label} result lacks an observation`);
}

function assertNoCapabilityVerdict(result) {
  assert.equal(Object.hasOwn(result, "capability"), false);
  assert.equal(Object.hasOwn(result, "decision"), false);
  assert.equal(Object.hasOwn(result, "verification_level"), false);
  assert.equal(Object.hasOwn(result.observation, "hypothesis"), false);
}

function summary(result) {
  return {
    run_id: result.run_id,
    operation_status: result.operation_status,
    completeness: result.observation.completeness,
    event_selectors: result.observation.event_changes.map((event) => event.selector.join(".")),
    analysis_gap_codes: result.observation.analysis_gaps.map((gap) => gap.code),
    request_fingerprint: result.observation.request_fingerprint,
    observation_fingerprint: result.observation.observation_fingerprint,
  };
}

function replaySummary(result) {
  return {
    status: result.status,
    comparison_ref: result.comparison_ref,
  };
}

function required(name) {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`${name} is required`);
  return value;
}
