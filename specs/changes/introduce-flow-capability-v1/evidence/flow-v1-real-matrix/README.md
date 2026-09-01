# Flow v1 real matrix evidence

`RESULTS.json` is the portable acceptance record for the verified Flow v1
boundary. It contains 20 vulnerable/fixed cases: five each for Python,
JavaScript, Java and C/C++.

Every case records:

- deterministic hashes of the vulnerable and fixed fixture trees;
- portable CodeQL database fingerprints;
- exact CodeQL and Flow-adapter versions;
- normalized FlowModel, observation, decision and verification level;
- SHA-256 hashes for generated queries and SARIF evidence;
- the result of model-free replay in a fresh Node process after copying the
  authoritative run to a different runs root.

The target databases are intentionally external dependencies. They are rebuilt
from the fixture trees using CodeQL `--build-mode=none`; no target build,
install or test script is executed. The results require CodeQL CLI and language
packs matching the recorded Analyzer provenance.

Re-run from the V2 workspace with:

```text
FLOW_REPORT_PATH=specs/changes/introduce-flow-capability-v1/evidence/flow-v1-real-matrix/RESULTS.json npm run test:flow-golden-real
```
