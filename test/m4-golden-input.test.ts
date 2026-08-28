import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { buildSourceContext } from "./m4-golden-input.mjs";

describe("M4 model input source context", () => {
  it("includes deterministic vulnerable source files and excludes generated directories", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-m4-input-"));
    try {
      await mkdir(join(root, "src"), { recursive: true });
      await mkdir(join(root, "node_modules", "ignored"), { recursive: true });
      await writeFile(join(root, "src", "z.py"), "sink(value)\n", "utf8");
      await writeFile(join(root, "src", "a.py"), "source = input()\n", "utf8");
      await writeFile(join(root, "src", "README.md"), "not executable source\n", "utf8");
      await writeFile(join(root, "node_modules", "ignored", "bad.py"), "secret()\n", "utf8");

      const context = await buildSourceContext(root, "python");

      expect(context.files.map((file) => file.path)).toEqual(["src/a.py", "src/z.py"]);
      expect(context.files[0]).toMatchObject({ path: "src/a.py", content: "source = input()\n", truncated: false });
      expect(context.root).toBe(root);
      expect(context.truncated_files).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("enforces per-file and aggregate byte limits deterministically", async () => {
    const root = await mkdtemp(join(tmpdir(), "autovul-m4-input-limit-"));
    try {
      await mkdir(join(root, "src"), { recursive: true });
      await writeFile(join(root, "src", "a.py"), "1234567890", "utf8");
      await writeFile(join(root, "src", "b.py"), "abcdefghij", "utf8");

      const context = await buildSourceContext(root, "python", { maxFileBytes: 6, maxTotalBytes: 8 });

      expect(context.files).toHaveLength(2);
      expect(context.files[0]?.path).toBe("src/a.py");
      expect(context.files[0]?.content).toBe("123456");
      expect(context.files[0]?.truncated).toBe(true);
      expect(context.files[1]).toMatchObject({ path: "src/b.py", content: "ab", truncated: true });
      expect(context.truncated_files).toBe(2);
      expect(context.total_bytes).toBe(8);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
