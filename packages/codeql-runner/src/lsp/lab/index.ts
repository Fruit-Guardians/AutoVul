// Explicitly non-production export surface for protocol discovery and matrix snapshots.
export {
  CodeqlLspProtocolSpike,
  l0UriForPath,
  readL0Document,
  type CodeqlLspProtocolSpikeOptions,
  type L0DiagnosticObservation,
  type L0DiagnosticItem,
  type L0DocumentObservation,
  type L0ProtocolDocument,
  type L0ProtocolSnapshot,
  type L0RequestObservation,
  type L0SymbolLocation,
  type L0TimelineEvent,
  type L0VisibleFilesMode,
  type L0WorkspaceUpdate,
  type L0WorkspaceFolder,
} from "./protocol-spike.js";
export { SessionRouter, type L0SessionTopology, type SessionRoute, type SessionRouteRequest, type SessionRouterOptions } from "../session-router.js";
