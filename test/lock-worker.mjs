import { NodeFileSystemPort } from "../packages/codeql-runner/dist/node-filesystem.js";

const lockPath = process.argv[2];
const holdMs = Number(process.argv[3] ?? "100");

if (lockPath === undefined) {
  process.stderr.write("missing lock path\n");
  process.exit(2);
}

try {
  const lock = await new NodeFileSystemPort().acquireLock(lockPath);
  process.stdout.write(`${JSON.stringify({ status: "acquired", pid: process.pid })}\n`);
  await new Promise((resolve) => setTimeout(resolve, holdMs));
  await lock.release();
} catch (error) {
  const code = typeof error === "object" && error !== null && "code" in error ? error.code : "UNKNOWN";
  process.stdout.write(`${JSON.stringify({ status: "rejected", code })}\n`);
  if (code !== "RUN_LOCKED") {
    process.exitCode = 1;
  }
}
