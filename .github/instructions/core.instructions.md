---
applyTo: "packages/core/**/*.ts"
---

# Core rules

- Core contains deterministic domain policy, workflow state, budgets and acceptance decisions.
- Use Ports for filesystem, processes, clocks, identifiers, artifacts and analyzers.
- Do not import host SDKs, UI code, concrete model providers or shell implementations.
- Preserve cancellation, timeout, locking, atomic state and resumability semantics.
- Model suggestions are candidates; only structured analyzer observations can advance verification state.
