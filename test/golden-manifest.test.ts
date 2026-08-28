import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { GoldenManifestSchema, parseSchema, type GoldenManifest } from "@autovul/contracts";

const manifestPath = join(dirname(fileURLToPath(import.meta.url)), "../../test/golden/manifest.json");

describe("shared Golden Case manifest", () => {
  it("is readable by the V2 TypeScript contracts and points to fixed fixtures", async () => {
    const payload: unknown = JSON.parse(await readFile(manifestPath, "utf8"));
    const manifest = parseSchema(GoldenManifestSchema, payload, "golden manifest");

    expect(manifest.manifest_schema_version).toBe("golden.manifest/v1");
    expect(manifest.cases).toHaveLength(20);
    for (const goldenCase of manifest.cases) {
      expect(goldenCase.source.vulnerable).toBeTruthy();
      expect(goldenCase.source.fixed).toBeTruthy();
      expect(goldenCase.expected.fixed.max_results).toBe(0);
      expect(goldenCase.expected.fixed.max_code_flows).toBe(0);
    }
  });

  it("rejects a malformed case contract", async () => {
    const payload: GoldenManifest = parseSchema(
      GoldenManifestSchema,
      JSON.parse(await readFile(manifestPath, "utf8")) as unknown,
      "golden manifest",
    );
    const invalid: unknown = {
      ...payload,
      cases: payload.cases.map((goldenCase, index) => (index === 0 ? { ...goldenCase, case_id: "invalid id" } : goldenCase)),
    };
    expect(() => parseSchema(GoldenManifestSchema, invalid, "golden manifest")).toThrow();
  });
});
