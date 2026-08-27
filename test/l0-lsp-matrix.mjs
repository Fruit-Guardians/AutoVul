import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import {
  CodeqlLspProtocolSpike,
  SessionRouter,
  l0UriForPath,
} from "@pure-auto-codeql/codeql-runner/lab";

const testRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(testRoot, "..");
const codeqlPath = process.env.CODEQL_PATH ?? "codeql";
const diagnosticsTimeoutMs = Number(process.env.CODEQL_L0_DIAGNOSTICS_TIMEOUT_MS ?? 20_000);
const initializationTimeoutMs = Number(process.env.CODEQL_L0_INIT_TIMEOUT_MS ?? 45_000);
const requestTimeoutMs = Number(process.env.CODEQL_L0_REQUEST_TIMEOUT_MS ?? 12_000);

const languageCases = [
  { language: "python", packName: "python_command_injection", completionToken: "TaintTracking::" },
  { language: "javascript", packName: "javascript_command_injection", completionToken: "TaintTracking::" },
  { language: "java", packName: "java_path_traversal", completionToken: "TaintTracking::" },
  { language: "cpp", packName: "cpp_buffer_overflow", completionToken: "TaintTracking::" },
];

const requestedLanguages = process.env.CODEQL_L0_LANGUAGES?.split(",").map((value) => value.trim()).filter(Boolean);
const selectedLanguageCases = requestedLanguages === undefined || requestedLanguages.length === 0
  ? languageCases
  : languageCases.filter(({ language }) => requestedLanguages.includes(language));

const matrixScenarioFilter = process.env.CODEQL_L0_MATRIX_SCENARIOS?.split(",").map((value) => value.trim()).filter(Boolean);

export async function runL0Matrix() {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "pure-auto-codeql-l0-"));
  const cacheRoot = join(fixtureRoot, "common-caches");
  await mkdir(cacheRoot, { recursive: true });
  const distributionRoot = resolveDistributionRoot();
  const codeqlVersion = readCodeqlVersion();
  const router = new SessionRouter();

  try {
    const fixtures = await createSemanticFixtures(fixtureRoot);
    const scenarioDefinitions = buildScenarioDefinitions({ cacheRoot, distributionRoot, fixtures });
    const definitions = matrixScenarioFilter === undefined || matrixScenarioFilter.length === 0
      ? scenarioDefinitions
      : scenarioDefinitions.filter(({ id }) => matrixScenarioFilter.includes(id));
    const scenarios = [];
    for (const definition of definitions) {
      scenarios.push(await runScenario(definition, { distributionRoot, repositoryRoot }));
    }

    return {
      schemaVersion: "v2.l0.codeql-lsp-matrix/1",
      codeqlVersion,
      generatedAt: new Date().toISOString(),
      client: {
        package: "@pure-auto-codeql/codeql-runner",
        transport: "vscode-jsonrpc/stdio",
        runtime: "headless-node",
      },
      topology: {
        selected: router.topology,
        policy: "shared-default-until-reproducible-starvation",
      },
      matrix: {
        diagnosticsTimeoutMs,
        initializationTimeoutMs,
        requestTimeoutMs,
        selectedLanguages: selectedLanguageCases.map(({ language }) => language),
        selectedScenarios: definitions.map(({ id }) => id),
        dimensions: [
          "synchronous",
          "visible-files",
          "workspace-add-mode",
          "document-order",
          "cache-temperature",
          "search-path-layout",
          "symbol-resolution-after-workspace-or-qlpack-update",
        ],
      },
      scenarios,
      summary: summarizeMatrix(scenarios),
    };
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

async function runScenario(definition, context) {
  const workspaceFolders = selectedLanguageCases.map(({ language, packName }) => {
    const folderPath = resolve(repositoryRoot, "test", "golden", packName);
    return { uri: l0UriForPath(folderPath), name: `golden-${language}` };
  });
  const orderedCases = orderCases(definition.documentOrder);
  const documents = await Promise.all(orderedCases.map(({ language, packName, completionToken }) => createDocument({
    language,
    packName,
    scenarioId: definition.id,
    completionToken,
  })));

  let initialWorkspaceFolders = workspaceFolders;
  let dynamicWorkspaceFolders = [];
  let semanticDocuments = [];
  let workspaceUpdateHook;
  let workspaceUpdates = [];

  if (definition.workspaceMode === "dynamic" && definition.kind === undefined) {
    initialWorkspaceFolders = workspaceFolders.slice(0, 1);
    dynamicWorkspaceFolders = workspaceFolders.slice(1);
  } else if (definition.kind === "workspace-add") {
    initialWorkspaceFolders = workspaceFolders.slice(0, 1);
    dynamicWorkspaceFolders = [definition.fixtures.dynamic.folder];
    semanticDocuments = [definition.fixtures.dynamic.document];
  } else if (definition.kind === "workspace-add-no-add") {
    initialWorkspaceFolders = workspaceFolders.slice(0, 1);
    semanticDocuments = [definition.fixtures.dynamic.document];
  } else if (definition.kind === "qlpack-update") {
    initialWorkspaceFolders = [definition.fixtures.update.folder];
    semanticDocuments = [definition.fixtures.update.document];
    workspaceUpdateHook = definition.fixtures.update.applyUpdate;
    workspaceUpdates = [{ watchedUri: definition.fixtures.update.qlpackUri }];
  } else if (definition.kind === "qlpack-update-baseline") {
    initialWorkspaceFolders = [definition.fixtures.updateBaseline.folder];
    semanticDocuments = [definition.fixtures.updateBaseline.document];
  }

  const allDocuments = semanticDocuments.length > 0 ? semanticDocuments : documents;
  const searchPaths = searchPathsFor(definition.searchPathLayout, workspaceFolders, context.distributionRoot);
  const commonCaches = definition.commonCaches;
  const route = new SessionRouter().route({
    distributionKey: context.distributionRoot,
    packGraphKey: workspaceGraphKey(initialWorkspaceFolders, dynamicWorkspaceFolders),
    workspaceFolderUris: [...initialWorkspaceFolders, ...dynamicWorkspaceFolders].map(({ uri }) => uri),
  });
  const spike = new CodeqlLspProtocolSpike({
    codeqlPath,
    searchPaths,
    workspaceFolders: initialWorkspaceFolders,
    dynamicWorkspaceFolders,
    dynamicWorkspaceAddMode: definition.workspaceMode === "dynamic" || definition.kind === "workspace-add" ? "one-by-one" : "batch",
    documents: allDocuments,
    visibleFilesMode: definition.visibleMode,
    commonCaches,
    workspaceUpdates,
    workspaceUpdateHook,
    cwd: context.repositoryRoot,
    initializationTimeoutMs,
    requestTimeoutMs,
    diagnosticsTimeoutMs,
    synchronous: definition.synchronous,
  });

  try {
    const snapshot = await spike.run();
    return {
      id: definition.id,
      kind: definition.kind ?? "protocol",
      config: {
        synchronous: definition.synchronous,
        visibleMode: definition.visibleMode,
        workspaceMode: definition.workspaceMode ?? "initial",
        workspaceAddMode: definition.workspaceMode === "dynamic" || definition.kind === "workspace-add" ? "one-by-one" : "batch",
        documentOrder: definition.documentOrder,
        cacheTemperature: definition.cacheTemperature,
        searchPathLayout: definition.searchPathLayout,
        commonCaches,
      },
      route,
      snapshot,
      observations: summarizeScenario(snapshot, definition),
    };
  } catch (error) {
    return {
      id: definition.id,
      kind: definition.kind ?? "protocol",
      config: {
        synchronous: definition.synchronous,
        visibleMode: definition.visibleMode,
        workspaceMode: definition.workspaceMode ?? "initial",
        documentOrder: definition.documentOrder,
        cacheTemperature: definition.cacheTemperature,
        searchPathLayout: definition.searchPathLayout,
        commonCaches,
      },
      route,
      error: error instanceof Error ? error.message : String(error),
      observations: { status: "runner-error" },
    };
  }
}

function buildScenarioDefinitions({ cacheRoot, distributionRoot, fixtures }) {
  const shared = {
    synchronous: false,
    visibleMode: "active-document",
    workspaceMode: "initial",
    documentOrder: "normal",
    cacheTemperature: "default",
    searchPathLayout: "pack-roots-plus-distribution",
    commonCaches: undefined,
  };
  return [
    { id: "baseline-async-active-initial-pack-roots", ...shared },
    { id: "synchronous-async-control", ...shared, synchronous: true },
    { id: "all-visible-control", ...shared, visibleMode: "all" },
    { id: "dynamic-add-one-by-one", ...shared, workspaceMode: "dynamic" },
    { id: "cpp-first-cold", ...shared, documentOrder: "cpp-first", cacheTemperature: "cold", commonCaches: join(cacheRoot, "cpp-compare") },
    { id: "cpp-last-warm", ...shared, documentOrder: "cpp-last", cacheTemperature: "warm", commonCaches: join(cacheRoot, "cpp-compare") },
    { id: "search-path-distribution-only", ...shared, searchPathLayout: "distribution-only" },
    { id: "search-path-workspace-parent", ...shared, searchPathLayout: "workspace-parent" },
    { id: "search-path-pack-roots-plus-distribution", ...shared },
    { id: "workspace-add-no-add", ...shared, kind: "workspace-add-no-add", searchPathLayout: "distribution-only", fixtures },
    { id: "workspace-add-dynamic", ...shared, kind: "workspace-add", workspaceMode: "dynamic", searchPathLayout: "distribution-only", fixtures },
    { id: "qlpack-update-baseline", ...shared, kind: "qlpack-update-baseline", searchPathLayout: "distribution-only", fixtures },
    { id: "qlpack-update-watched", ...shared, kind: "qlpack-update", searchPathLayout: "distribution-only", fixtures },
  ];
}

async function createDocument({ language, packName, scenarioId, completionToken }) {
  const queryPath = resolve(repositoryRoot, "test", "golden", packName, "query.ql");
  const text = await readFile(queryPath, "utf8");
  const virtualPath = resolve(repositoryRoot, "test", "golden", packName, ".l0-virtual", scenarioId, `${language}.ql`);
  const invalidPath = resolve(repositoryRoot, "test", "golden", packName, ".l0-virtual", scenarioId, `${language}-invalid.ql`);
  return {
    language,
    uri: l0UriForPath(virtualPath),
    invalidUri: l0UriForPath(invalidPath),
    text,
    invalidText: "this is deliberately invalid QL syntax",
    definitionToken: "DataFlow",
    completionToken,
  };
}

function orderCases(order) {
  if (order === "cpp-first") {
    return [...selectedLanguageCases].sort(({ language }) => language === "cpp" ? -1 : 1);
  }
  if (order === "cpp-last") {
    return [...selectedLanguageCases].sort(({ language }) => language === "cpp" ? 1 : -1);
  }
  return selectedLanguageCases;
}

function searchPathsFor(layout, workspaceFolders, distributionRoot) {
  const packRoots = workspaceFolders.map(({ uri }) => fileURLToPath(uri));
  if (layout === "distribution-only") {
    return [distributionRoot];
  }
  if (layout === "workspace-parent") {
    return [resolve(repositoryRoot, "test", "golden"), distributionRoot];
  }
  return [...packRoots, distributionRoot];
}

function summarizeScenario(snapshot, definition) {
  const documents = snapshot.documents.map((document) => ({
    language: document.language,
    validReceived: document.valid.received,
    validDiagnostics: document.valid.count,
    validLatencyMs: document.valid.elapsedMs,
    invalidReceived: document.invalid.received,
    invalidDiagnostics: document.invalid.count,
    invalidLatencyMs: document.invalid.elapsedMs,
    definitionCompleted: document.definition.completed,
    definitionLocations: document.definition.locations ?? [],
    definitionResultCount: document.definition.resultCount ?? 0,
    hoverCompleted: document.hover.completed,
    hoverHasText: Boolean(document.hover.hoverText),
    completionCompleted: document.completion.completed,
    completionItems: document.completion.resultCount ?? 0,
    completionLabels: document.completion.completionLabels ?? [],
  }));
  return {
    status: snapshot.transport.cleanShutdown ? "observed" : "unclean-shutdown",
    capabilities: snapshot.capabilitySummary,
    validDiagnosticsReceived: documents.filter(({ validReceived }) => validReceived).length,
    validClean: documents.filter(({ validReceived, validDiagnostics }) => validReceived && validDiagnostics === 0).length,
    definitionWithLocations: documents.filter(({ definitionLocations }) => definitionLocations.length > 0).length,
    hoverWithText: documents.filter(({ hoverHasText }) => hoverHasText).length,
    completionWithItems: documents.filter(({ completionItems }) => completionItems > 0).length,
    documents,
    dynamicWorkspaceNotificationSent: snapshot.workspace.dynamicWorkspaceFoldersNotificationSent,
    visibleFilesUpdateCount: snapshot.workspace.visibleFilesUpdateCount,
    watchedFilesNotificationSent: snapshot.workspace.watchedFilesNotificationSent,
    workspaceUpdates: snapshot.workspace.workspaceUpdates,
    expectedSemanticProbe: definition.kind === undefined ? undefined : definition.kind,
  };
}

function summarizeMatrix(scenarios) {
  const successful = scenarios.filter(({ snapshot }) => snapshot !== undefined);
  return {
    scenarioCount: scenarios.length,
    runnerErrors: scenarios.filter(({ error }) => error !== undefined).length,
    cleanShutdowns: successful.filter(({ snapshot }) => snapshot.transport.cleanShutdown).length,
    diagnosticsReceived: successful.filter(({ snapshot }) => snapshot.capabilitySummary.diagnostics).length,
    definitionCapabilities: successful.filter(({ snapshot }) => snapshot.capabilitySummary.definition).length,
    hoverCapabilities: successful.filter(({ snapshot }) => snapshot.capabilitySummary.hover).length,
    completionCapabilities: successful.filter(({ snapshot }) => snapshot.capabilitySummary.completion).length,
  };
}

async function createSemanticFixtures(root) {
  const dynamicRoot = join(root, "dynamic-pack");
  await mkdir(dynamicRoot, { recursive: true });
  const dynamicQuery = await readFile(resolve(repositoryRoot, "test", "golden", "python_command_injection", "query.ql"), "utf8");
  await writeFile(join(dynamicRoot, "qlpack.yml"), "name: pure-auto-codeql/l0-dynamic\nversion: 0.0.1\ndependencies:\n  codeql/python-all: \"*\"\n", "utf8");
  const dynamicQueryPath = join(dynamicRoot, "query.ql");
  await writeFile(dynamicQueryPath, dynamicQuery, "utf8");

  const update = await createUpdateFixture(root, "update");
  const updateBaseline = await createUpdateFixture(root, "update-baseline");
  return {
    dynamic: {
      folder: { uri: l0UriForPath(dynamicRoot), name: "l0-dynamic" },
      document: makeFixtureDocument(dynamicQueryPath, "python", "dynamic", dynamicQuery),
    },
    update,
    updateBaseline,
  };
}

async function createUpdateFixture(root, name) {
  const fixtureRoot = join(root, name);
  await mkdir(fixtureRoot, { recursive: true });
  const qlpackPath = join(fixtureRoot, "qlpack.yml");
  const queryPath = join(fixtureRoot, "query.ql");
  const query = "import javascript\n\nselect \"l0 qlpack update\"\n";
  await writeFile(qlpackPath, "name: pure-auto-codeql/l0-update\nversion: 0.0.1\ndependencies:\n  codeql/python-all: \"*\"\n", "utf8");
  await writeFile(queryPath, query, "utf8");
  return {
    folder: { uri: l0UriForPath(fixtureRoot), name: `l0-${name}` },
    qlpackUri: l0UriForPath(qlpackPath),
    document: makeFixtureDocument(queryPath, "javascript", name, query),
    applyUpdate: async () => {
      await writeFile(qlpackPath, "name: pure-auto-codeql/l0-update\nversion: 0.0.2\ndependencies:\n  codeql/javascript-all: \"*\"\n", "utf8");
    },
  };
}

function makeFixtureDocument(queryPath, language, name, text) {
  return {
    language,
    uri: l0UriForPath(join(dirname(queryPath), ".l0-virtual", `${name}.ql`)),
    invalidUri: l0UriForPath(join(dirname(queryPath), ".l0-virtual", `${name}-invalid.ql`)),
    text,
    invalidText: "this is deliberately invalid QL syntax",
    definitionToken: language === "javascript" ? "javascript" : "DataFlow",
    completionToken: language === "javascript" ? "javascript" : "DataFlow::",
  };
}

function workspaceGraphKey(initialWorkspaceFolders, dynamicWorkspaceFolders) {
  return [...initialWorkspaceFolders, ...dynamicWorkspaceFolders].map(({ uri }) => uri).sort().join("|");
}

function resolveDistributionRoot() {
  if (process.env.CODEQL_DISTRIBUTION_ROOT !== undefined) {
    return process.env.CODEQL_DISTRIBUTION_ROOT;
  }
  try {
    const resolvedCodeql = execFileSync("which", [codeqlPath], { encoding: "utf8" }).trim();
    return dirname(resolvedCodeql);
  } catch {
    return resolve(repositoryRoot, "..", "..", "tools", "codeql");
  }
}

function readCodeqlVersion() {
  try {
    return execFileSync(codeqlPath, ["version"], { cwd: repositoryRoot, encoding: "utf8" }).trim().split("\n")[0] ?? "unknown";
  } catch (error) {
    return `unavailable: ${error instanceof Error ? error.message : String(error)}`;
  }
}
