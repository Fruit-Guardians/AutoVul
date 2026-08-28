#!/usr/bin/env node

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

/** Parse the JSONL event stream emitted by `pi --mode json`. */
export function parsePiJsonOutput(stdout) {
  const events = stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });
  const assistantMessages = [];
  for (const event of events) {
    if (event.type === "message_end" && event.message?.role === "assistant") assistantMessages.push(event.message);
    if (event.type === "agent_end" && Array.isArray(event.messages)) {
      assistantMessages.push(...event.messages.filter((message) => message?.role === "assistant"));
    }
  }
  const message = [...assistantMessages].reverse().find((item) => Array.isArray(item.content) && item.content.some((block) => block?.type === "text"));
  if (message === undefined) {
    const errorMessage = [...assistantMessages].reverse().find((item) => typeof item.errorMessage === "string")?.errorMessage;
    throw new Error(errorMessage === undefined ? "PI_GENERATOR_JSON_MISSING" : `PI_GENERATOR_FAILED: ${errorMessage}`);
  }
  const text = message.content
    .filter((block) => block?.type === "text" && typeof block.text === "string")
    .map((block) => block.text)
    .join("\n")
    .trim();
  const jsonText = stripJsonFence(text);
  let value;
  try {
    value = JSON.parse(jsonText);
  } catch (error) {
    throw new Error(`PI_GENERATOR_JSON_INVALID: ${error instanceof Error ? error.message : "parse error"}`);
  }
  const usage = [...events]
    .reverse()
    .map((event) => event.type === "turn_end" ? event.message?.usage : event.type === "message_end" ? event.message?.usage : undefined)
    .find((item) => item !== undefined);
  return {
    value,
    provider: message.provider,
    model: message.model,
    usage,
  };
}

async function main() {
  const input = JSON.parse(await readStdin());
  const args = buildPiArgs(input, process.env);
  const provider = process.env.AUTOVUL_M4_PI_PROVIDER;
  const model = process.env.AUTOVUL_M4_PI_MODEL;
  const thinking = process.env.AUTOVUL_M4_PI_THINKING ?? "medium";
  const result = await runPi(args);
  const parsed = parsePiJsonOutput(result.stdout);
  const candidate = parsed.value?.candidate ?? parsed.value;
  if (typeof candidate !== "object" || candidate === null || candidate.intent === undefined) {
    throw new Error("PI_GENERATOR_INTENT_MISSING");
  }
  const usage = parsed.usage;
  if (usage === undefined || !Number.isFinite(usage.input) || !Number.isFinite(usage.output)) {
    throw new Error("PI_GENERATOR_USAGE_MISSING");
  }
  const inputTokens = usage.input;
  const outputTokens = usage.output;
  process.stdout.write(JSON.stringify({
    candidate,
    metadata: {
      provider: parsed.provider ?? provider ?? "pi-configured-provider",
      model: parsed.model ?? model ?? "pi-configured-model",
      adapter_version: "m4-pi-host/1",
      parameters: { thinking, tools: false },
      usage: {
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        total_tokens: Number.isFinite(usage.totalTokens) ? usage.totalTokens : inputTokens + outputTokens,
      },
    },
  }));
}

export function buildPiArgs(input, env = process.env) {
  const provider = env.AUTOVUL_M4_PI_PROVIDER;
  const model = env.AUTOVUL_M4_PI_MODEL;
  const thinking = env.AUTOVUL_M4_PI_THINKING ?? "medium";
  const args = [
    "--no-session",
    "--no-tools",
    "--no-skills",
    "--no-prompt-templates",
    "--no-themes",
    "--no-context-files",
    "--system-prompt",
    "You are a strict JSON adapter. Reply with exactly one RFC 8259 JSON object on one line. Never use markdown, code fences, comments, trailing commas, or literal newlines/unescaped double quotes inside JSON strings.",
    "--thinking",
    thinking,
    "--mode",
    "json",
  ];
  if (env.AUTOVUL_M4_PI_NO_EXTENSIONS === "true") args.push("--no-extensions");
  if (provider !== undefined) args.push("--provider", provider);
  if (model !== undefined) args.push("--model", model);
  args.push(
    "-p",
    [
      "You are the query-synthesis model inside the host Pi Agent Loop.",
      "Return JSON only. Do not use markdown and do not return ql_text.",
      "Return exactly {candidate:{candidate_id,query_id,intent,rationale}}.",
      "The intent must use only the selected language pack and must identify one concrete Source and Sink supported by the vulnerable source context.",
      "The intent has required top-level keys schema_version, intent_id, language, cwe, query_kind, flow_mode, source, sink, message; use schema_version exactly v2.contracts/1, query_kind exactly path-problem, and flow_mode value or taint.",
      "Each source/sink matcher must contain a kind plus only its allowed fields: kind is call, call_argument, constructor, function, parameter, environment, property, array_index, or array_element; allowed fields are module, type, member, name, argument_index, argument_name, property, file, symbol, line.",
      "For explicit wrapper, conversion, pointer, or variadic boundaries, use additional_flow_steps with directed structured matchers: call_argument -> call for a conversion return, call_argument -> parameter for an argument entering a callee, and parameter/call_argument -> the next concrete endpoint when the CodeQL probe establishes that boundary. Never use an unbounded any-call matcher or raw ql_text.",
      languageMatcherGuidance(input.language),
      "Use previous_feedback, including schema issue paths, to repair the intent. Never invent a database result, never use a reference query or reference intent, and do not create a database.",
      JSON.stringify(input),
    ].join("\n\n"),
  );
  return args;
}

function languageMatcherGuidance(language) {
  if (language === "javascript" || language === "typescript") {
    return "JavaScript/TypeScript matcher guidance: call_argument is unsupported; use call for the whole call. A property-chain source such as process.env.NAME must be {\"kind\":\"property\",\"module\":\"process\",\"property\":\"env.NAME\"}; a member call such as child_process.exec(value) must be {\"kind\":\"call\",\"module\":\"child_process\",\"member\":\"exec\",\"argument_index\":0}.";
  }
  if (language === "python") {
    return "Python matcher guidance: represent module calls with {\"kind\":\"call\",\"module\":\"module_name\",\"member\":\"function_name\"}; use argument_index for a sink argument, and use {\"kind\":\"environment\",\"name\":\"getenv\"} for os.getenv().";
  }
  if (language === "java" || language === "kotlin") {
    return "Java/Kotlin matcher guidance: represent method calls with {\"kind\":\"call\",\"type\":\"qualified.Type\",\"name\":\"methodName\"}; use argument_index for a sink argument and use the exact declaring type when the source is a library method.";
  }
  if (language === "cpp" || language === "c") {
    return "C/C++ matcher guidance: a formal input may be {\"kind\":\"parameter\",\"name\":\"param\",\"file\":\"relative/file.c\",\"symbol\":\"enclosing_function\",\"line\":123}; use {\"kind\":\"call_argument\",\"name\":\"callee\",\"argument_index\":0,\"file\":\"relative/file.c\",\"line\":456} for an exact argument endpoint, and prefer the exact global function name observed in source context."
  }
  return "Choose matcher fields from the selected language pack and the concrete symbols observed in source_context.";
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function stripJsonFence(text) {
  const fenced = text.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  if (fenced?.[1] !== undefined) return fenced[1].trim();
  const first = text.indexOf("{");
  const last = text.lastIndexOf("}");
  return first >= 0 && last > first ? text.slice(first, last + 1) : text;
}

function runPi(args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn("pi", args, {
      cwd: process.cwd(),
      env: process.env,
      shell: false,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    const timer = setTimeout(() => {
      try { process.kill(-child.pid, "SIGTERM"); } catch { child.kill("SIGTERM"); }
    }, 180_000);
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      const output = Buffer.concat(stdout).toString("utf8");
      if (code !== 0 && output.length === 0) {
        reject(new Error(`PI_GENERATOR_PROCESS_FAILED: ${code ?? signal}: ${Buffer.concat(stderr).toString("utf8").slice(-2000)}`));
        return;
      }
      resolvePromise({ stdout: output });
    });
  });
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
