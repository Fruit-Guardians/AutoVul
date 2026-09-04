# @autovul/cli

`@autovul/cli` provides the deterministic command-line interface for AutoVul.

The CLI is a debugging, CI, status, cancellation, and model-free replay interface over the shared Application API. It does not plan research or run an Agent loop. Availability of a command branch does not by itself mean the underlying Capability or Analyzer Service is verified; see the root project progress table.

## Commands

### Environment & Database
```bash
# Verify CodeQL environment and language tools
autovul doctor [--json]

# Inspect a prebuilt CodeQL database
autovul database inspect <db-path> [--json]

# Validate a CodeQL database
autovul database validate <db-path> [--json]
```

### Research & Replay
```bash
# Validate a research hypothesis schema without running analyzers
autovul research validate --request <request.json> [--json]

# Execute a research hypothesis or analyzer service
autovul research execute --request <request.json> [--json]

# Check the status of an existing run
autovul run status <run-id> [--json]

# Cancel an active in-flight run
autovul run cancel <run-id> [--json]

# Deterministically replay an execution without model involvement
autovul run replay <run-id> [--json]
```

### Query Pack Replay
```bash
# Replay a finalized Query Pack against relocated vulnerable/fixed databases
autovul query-pack verify <pack-dir> \
  --vulnerable-db <path> \
  --fixed-db <path> \
  [--workspace-root <path>] \
  [--json]
```

## Global Options

- `--json`: Output machine-readable JSON envelope `{ ok: boolean, result?: any, error?: DomainErrorRecord }`.
- `--runs-dir <path>`: Directory where run manifests and artifacts are stored (default: `./runs`).
- `--workspace-root <path>`: Trusted root directory for paths and repositories.
- `--codeql <path>`: Path to `codeql` executable (default: `codeql` in PATH).
- `--timeout-ms <ms>`: Global operation timeout in milliseconds.
