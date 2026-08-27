---
applyTo: "packages/pi-extension/**/*.ts,packages/cli/**/*.ts"
---

# Integration rules

- Integrations register tools and commands, translate parameters, render results and manage host lifecycle.
- Do not duplicate workflow decisions or analyzer command construction here.
- Use the shared Application API and versioned contracts.
- Keep model-visible tools few, stable and domain-oriented.
- Return compact structured feedback and preserve full evidence in run artifacts.
