export type L0SessionTopology = "shared" | "pack-graph";

export interface SessionRouteRequest {
  readonly distributionKey: string;
  readonly packGraphKey: string;
  readonly workspaceFolderUris: readonly string[];
}

export interface SessionRoute {
  readonly sessionId: string;
  readonly topology: L0SessionTopology;
  readonly distributionKey: string;
  readonly packGraphKey: string;
  readonly workspaceFolderUris: readonly string[];
}

export interface SessionRouterOptions {
  readonly topology?: L0SessionTopology;
}

/**
 * Keeps session topology out of the language-service API.
 *
 * The default is deliberately shared. Pack-graph sharding is an explicit,
 * deterministic compatibility result, not an automatic response to a single
 * timeout. This router only calculates ownership; process lifecycle remains
 * with the session manager that will consume the route in L2.
 */
export class SessionRouter {
  private readonly selectedTopology: L0SessionTopology;

  constructor(options: SessionRouterOptions = {}) {
    this.selectedTopology = options.topology ?? "shared";
  }

  get topology(): L0SessionTopology {
    return this.selectedTopology;
  }

  route(request: SessionRouteRequest): SessionRoute {
    const workspaceFolderUris = [...new Set(request.workspaceFolderUris)].sort();
    const sessionKey = this.selectedTopology === "shared"
      ? `shared:${request.distributionKey}`
      : `pack-graph:${request.distributionKey}:${request.packGraphKey}`;
    return {
      sessionId: sessionKey,
      topology: this.selectedTopology,
      distributionKey: request.distributionKey,
      packGraphKey: request.packGraphKey,
      workspaceFolderUris,
    };
  }
}
