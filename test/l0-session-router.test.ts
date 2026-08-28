import { describe, expect, it } from "vitest";

import { SessionRouter } from "@autovul/codeql-runner";

describe("SessionRouter", () => {
  it("defaults to one shared deterministic session", () => {
    const router = new SessionRouter();
    const first = router.route({
      distributionKey: "codeql-2.26.1",
      packGraphKey: "python",
      workspaceFolderUris: ["file:///b", "file:///a", "file:///a"],
    });
    const second = router.route({
      distributionKey: "codeql-2.26.1",
      packGraphKey: "cpp",
      workspaceFolderUris: ["file:///c"],
    });

    expect(first.topology).toBe("shared");
    expect(first.sessionId).toBe(second.sessionId);
    expect(first.workspaceFolderUris).toEqual(["file:///a", "file:///b"]);
  });

  it("supports explicit deterministic pack-graph sharding", () => {
    const router = new SessionRouter({ topology: "pack-graph" });
    const python = router.route({ distributionKey: "codeql-2.26.1", packGraphKey: "python", workspaceFolderUris: [] });
    const cpp = router.route({ distributionKey: "codeql-2.26.1", packGraphKey: "cpp", workspaceFolderUris: [] });

    expect(python.topology).toBe("pack-graph");
    expect(python.sessionId).not.toBe(cpp.sessionId);
    expect(python.sessionId).toBe("pack-graph:codeql-2.26.1:python");
  });
});
