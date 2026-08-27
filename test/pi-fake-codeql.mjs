#!/usr/bin/env node

const [command, subcommand] = process.argv.slice(2);
if (process.env.PI_FAKE_CODEQL_SLEEP === "1" && (command === "version" || (command === "resolve" && subcommand === "database"))) {
  await new Promise((resolve) => setTimeout(resolve, 30_000));
}

if (command === "version") {
  console.log("CodeQL CLI version 2.26.1");
} else if (command === "query" && subcommand === "compile") {
  // The Pi RPC M2 scenario validates workflow wiring with a fake CLI.
  process.exitCode = 0;
} else if (command === "database" && subcommand === "analyze") {
  const outputArgument = process.argv.find((argument) => argument.startsWith("--output="));
  if (outputArgument === undefined) {
    process.exitCode = 2;
  } else {
    const output = outputArgument.slice("--output=".length);
    const database = process.argv[4] ?? "";
    const results = database.includes("fixed") ? [] : [{
      ruleId: "fake/python-command-injection",
      locations: [{ physicalLocation: { artifactLocation: { uri: "app.py" }, region: { startLine: 5 } } }],
      codeFlows: [{ threadFlows: [] }],
    }];
    const { writeFile } = await import("node:fs/promises");
    await writeFile(output, JSON.stringify({ runs: [{ results }] }), "utf8");
  }
} else if (command === "resolve" && subcommand === "languages") {
  console.log("python (/fake/codeql/python)");
} else if (command === "resolve" && subcommand === "database") {
  console.log(JSON.stringify({ language: "python", codeqlVersion: "2.26.1" }));
} else {
  process.exitCode = 2;
}
