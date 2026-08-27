import { describe, expect, it } from "vitest";

import { sanitizedGeneratorEnvironment } from "./m4-golden-environment.mjs";

describe("M4 generator environment boundary", () => {
  it("forwards only explicitly approved host-model settings", () => {
    const result = sanitizedGeneratorEnvironment({
      ANTHROPIC_AUTH_TOKEN: "redacted-token",
      ANTHROPIC_BASE_URL: "https://model.example/v1",
      PI_CODING_AGENT_DIR: "/tmp/pi-agent",
      PURE_AUTO_CODEQL_M4_PI_MODEL: "host-model",
      HOME: "/Users/private",
      AWS_SECRET_ACCESS_KEY: "must-not-forward",
      UNRELATED_SETTING: "must-not-forward",
    });

    expect(result).toEqual({
      ANTHROPIC_AUTH_TOKEN: "redacted-token",
      ANTHROPIC_BASE_URL: "https://model.example/v1",
      PI_CODING_AGENT_DIR: "/tmp/pi-agent",
      PURE_AUTO_CODEQL_M4_PI_MODEL: "host-model",
    });
  });
});
