---
applyTo: "packages/contracts/**/*.ts"
---

# Contracts rules

- Contracts are versioned public protocols shared by every host integration.
- Do not import Pi, DeepSeek Harness, Node process, filesystem, UI or concrete analyzer implementations.
- Prefer strict TypeBox schemas with `additionalProperties: false` for model-facing input.
- New fields require an explicit compatibility decision and validation tests.
- Keep vulnerability-research domain concepts separate from CodeQL-only concepts when the concept can apply to another analyzer.
