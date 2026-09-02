import { describe, expect, it } from "vitest";

import { compareUtf8, sha256Utf8 } from "../packages/core/dist/change-observation/sha256.js";

describe("Change Observation portable SHA-256", () => {
  it("matches standard SHA-256 vectors without a Node runtime import", () => {
    expect(sha256Utf8("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256Utf8("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("orders canonical strings by UTF-8 bytes rather than locale", () => {
    expect(compareUtf8("src/a", "src/z")).toBeLessThan(0);
    expect(compareUtf8("src/é", "src/z")).toBeGreaterThan(0);
    expect(compareUtf8("src/é", "src/é")).toBe(0);
  });
});
