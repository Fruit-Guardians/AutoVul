import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { CODEQL_DISCOVERY_HINT } from "../packages/pi-extension/src/prompts.js";
import { DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS } from "../packages/deepseek-harness/src/prompts.js";

const root = resolve(import.meta.dirname, "..");
const playbooksDir = join(root, "playbooks");

const PLAYBOOK_FILES = [
  "patch-guided.md",
  "sink-guided.md",
  "protocol-guided.md",
  "variant-guided.md",
] as const;

const REQUIRED_SECTIONS = [
  "适用场景",
  "宿主原生自主阶段",
  "触发 AutoVul 的增强条件",
  "工具接口与调用规约",
  "结论回填与假设修正",
  "真实端到端案例",
];

describe("Host Semantic Audit Playbooks", () => {
  it("provides comprehensive playbooks directory with index", async () => {
    const readme = await readFile(join(playbooksDir, "README.md"), "utf8");
    expect(readme).toContain("Agent 原生审计优先");
    for (const file of PLAYBOOK_FILES) {
      expect(readme).toContain(file);
    }
  });

  for (const file of PLAYBOOK_FILES) {
    it(`verifies ${file} contains all 5 mandatory workflow dimensions and real case`, async () => {
      const content = await readFile(join(playbooksDir, file), "utf8");
      expect(content.length).toBeGreaterThan(500);

      for (const section of REQUIRED_SECTIONS) {
        expect(content).toContain(section);
      }
    });
  }

  it("references four playbooks in host prompt surfaces", () => {
    expect(CODEQL_DISCOVERY_HINT).toContain("patch-guided");
    expect(CODEQL_DISCOVERY_HINT).toContain("sink-guided");
    expect(CODEQL_DISCOVERY_HINT).toContain("protocol-guided");
    expect(CODEQL_DISCOVERY_HINT).toContain("variant-guided");

    expect(DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS).toContain("Patch-Guided");
    expect(DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS).toContain("Sink-Guided");
    expect(DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS).toContain("Protocol-Guided");
    expect(DEEPSEEK_HARNESS_SYSTEM_INSTRUCTIONS).toContain("Variant-Guided");
  });

  it("links playbooks in root README.md", async () => {
    const readme = await readFile(join(root, "README.md"), "utf8");
    expect(readme).toContain("Semantic audit playbooks");
    expect(readme).toContain("./playbooks/patch-guided.md");
    expect(readme).toContain("./playbooks/sink-guided.md");
    expect(readme).toContain("./playbooks/protocol-guided.md");
    expect(readme).toContain("./playbooks/variant-guided.md");
  });
});
