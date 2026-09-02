import { resolve } from "node:path";

import {
  Application,
  RandomIdGenerator,
  SystemClock,
  type ApplicationApi,
} from "@autovul/core";

import { LocalArtifactStore } from "./artifact-store.js";
import { CodeqlRunner } from "./codeql-runner.js";
import { NodeFileSystemPort } from "./node-filesystem.js";
import { CodeqlQueryRunner } from "./query-runner.js";
import { CodeqlLspDraftRunner } from "./lsp/draft-runner.js";
import { CodeqlFlowAdapter } from "./flow-adapter.js";
import { CodeqlMissingCheckAdapter } from "./missing-check-adapter.js";
import { CodeqlTypestateAdapter } from "./typestate-adapter.js";
import { GitChangeObservationAdapter } from "./change-observation-git-adapter.js";

export interface LocalApplicationOptions {
  readonly cwd?: string;
  readonly runsDir?: string;
  readonly workspaceRoot?: string;
  readonly codeqlPath?: string;
  readonly timeoutMs?: number;
}

export function createLocalApplication(options: LocalApplicationOptions = {}): ApplicationApi {
  const cwd = resolve(options.cwd ?? process.cwd());
  const trustedWorkspaceRoot = resolve(options.workspaceRoot ?? cwd);
  const filesystem = new NodeFileSystemPort();
  const runsDir = resolve(options.runsDir ?? `${cwd}/runs`);
  const executable = options.codeqlPath ?? process.env.CODEQL_PATH ?? "codeql";
  const codeql = options.codeqlPath === undefined
    ? new CodeqlRunner({ cwd, ...(options.workspaceRoot === undefined ? {} : { workspaceRoot: options.workspaceRoot }) })
    : new CodeqlRunner({ cwd, ...(options.workspaceRoot === undefined ? {} : { workspaceRoot: options.workspaceRoot }), executable: options.codeqlPath });
  const queries = new CodeqlQueryRunner({ filesystem, executable, cwd });
  const drafts = new CodeqlLspDraftRunner({
    executable,
    cwd,
    ...(process.env.CODEQL_DISTRIBUTION_ROOT === undefined ? {} : { distributionRoot: process.env.CODEQL_DISTRIBUTION_ROOT }),
  });
  const dependencies = {
    codeql,
    queries,
    probes: queries,
    flow: new CodeqlFlowAdapter(queries, queries),
    missingCheck: new CodeqlMissingCheckAdapter({ executable, cwd, filesystem }),
    typestate: new CodeqlTypestateAdapter({ executable, cwd, filesystem }),
    changeObservation: new GitChangeObservationAdapter({ trustedRoots: [trustedWorkspaceRoot], filesystem }),
    drafts,
    artifacts: new LocalArtifactStore(runsDir, filesystem),
    clock: new SystemClock(),
    ids: new RandomIdGenerator(),
  };
  if (options.timeoutMs === undefined) {
    return new Application(dependencies);
  }
  return new Application({
    ...dependencies,
    defaultTimeoutMs: options.timeoutMs,
  });
}
