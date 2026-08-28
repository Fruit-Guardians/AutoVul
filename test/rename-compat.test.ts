import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { readAutovulEnv } from "@autovul/codeql-runner";
import { qlpackForLanguage } from "@autovul/core";

describe("AutoVul rename compatibility", () => {
  it("prefers canonical environment names and falls back to the former names", () => {
    expect(readAutovulEnv("RUNS_DIR", { PURE_AUTO_CODEQL_V2_RUNS_DIR: "/legacy" })).toBe("/legacy");
    expect(readAutovulEnv("RUNS_DIR", { AUTOVUL_RUNS_DIR: "/canonical", PURE_AUTO_CODEQL_V2_RUNS_DIR: "/legacy" })).toBe("/canonical");
    expect(readAutovulEnv("M4_PI_MODEL", { PURE_AUTO_CODEQL_M4_PI_MODEL: "legacy-model" })).toBe("legacy-model");
    expect(readAutovulEnv("M4_PI_MODEL", { AUTOVUL_M4_PI_MODEL: "canonical-model", PURE_AUTO_CODEQL_M4_PI_MODEL: "legacy-model" })).toBe("canonical-model");
  });

  it("publishes one canonical CLI implementation under both binary names", async () => {
    const packageJson = JSON.parse(await readFile(join(process.cwd(), "packages/cli/package.json"), "utf8")) as {
      name: string;
      bin: Record<string, string>;
    };
    expect(packageJson.name).toBe("@autovul/cli");
    expect(packageJson.bin).toEqual({ autovul: "./dist/main.js", "pure-auto-codeql-v2": "./dist/main.js" });
  });

  it("uses AutoVul for new generated pack branding while keeping stable rule ids", () => {
    expect(qlpackForLanguage("python")).toContain("name: autovul/generated");
  });
});
