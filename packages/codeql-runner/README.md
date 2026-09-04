# @autovul/codeql-runner

`@autovul/codeql-runner` provides concrete analyzer adapters, operating system ports, and application assembly factories for AutoVul.

## Analyzers & Adapters

1. **CodeQL Runner & Language Server Adapter**:
   - `CodeqlRunner`: CodeQL database inspection and validation.
   - `CodeqlQueryRunner`: Authoritative query and probe execution via CodeQL CLI.
   - `CodeqlLspDraftRunner`: Advisory draft diagnostics via CodeQL Language Server.
   - Capability adapters use the verified language renderers for Python, JavaScript/TypeScript, Java/Kotlin, and C/C++ where their owning SPEC permits them.
2. **JavaScript AST CFG Adapter** (`JavascriptCfgMissingCheckAdapter`):
   - Fast, local, model-free AST and intra-procedural CFG analysis for missing check hypotheses.
   - Parses JS/TS syntax using the TypeScript parser, but verified semantics are strictly limited to JavaScript.
   - Checks bounded direct-call dominance and condition-polarity cases declared by its change SPEC without requiring prebuilt CodeQL databases.
3. **Git Change Observation Adapter** (`GitChangeObservationAdapter`):
   - Performs read-only inspection of immutable Git commit trees using `git cat-file -p`.
   - AST symbol traversal between base and head revisions within canonicalized `trustedRoots`.
4. **Git Variant Search Adapter** (`GitVariantSearchAdapter`):
   - Scans explicit target corpus revisions for symbol call patterns and enclosing signatures.
   - Parses selected JavaScript/TypeScript-family extensions and emits canonical SHA-256 candidate identities, structured gaps, atomic bundles, and replayable evidence.

## Application Factory

`createLocalApplication(options)` configures and wires all ports into a ready-to-use `Application`:

```typescript
import { createLocalApplication } from "@autovul/codeql-runner";

const app = createLocalApplication({
  workspaceRoot: process.cwd(),
  runsDir: "./runs",
  codeqlPath: "codeql",
});
```

`workspaceRoot` is also the trusted-root boundary used by the Git-backed adapters assembled by this factory.
