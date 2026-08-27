import { readFile } from "node:fs/promises";

const apiKey = process.env.PURE_AUTO_CODEQL_M2_API_KEY;
const apiBase = (process.env.PURE_AUTO_CODEQL_M2_API_BASE ?? "https://api.openai.com/v1").replace(/\/$/, "");
const model = process.env.PURE_AUTO_CODEQL_M2_MODEL;
const temperature = Number(process.env.PURE_AUTO_CODEQL_M2_TEMPERATURE ?? "0.2");
const maxTokens = Number(process.env.PURE_AUTO_CODEQL_M2_MAX_TOKENS ?? "4000");

if (apiKey === undefined || model === undefined) {
  throw new Error("PURE_AUTO_CODEQL_M2_API_KEY and PURE_AUTO_CODEQL_M2_MODEL are required");
}

const input = JSON.parse(await readFile(0, "utf8"));
const prompt = [
  "You are generating a Python CodeQL path query.",
  "Return JSON only with this shape: {\"candidate\":{\"ql_text\":\"...\",\"query_id\":\"...\",\"rationale\":\"...\"}}.",
  "Do not use or request a reference query. Use only the supplied vulnerability spec and diagnostics.",
  "The QL must compile, report the expected source-to-sink flow on the vulnerable database, and report zero results on the fixed database.",
  JSON.stringify(input),
].join("\n\n");

const response = await fetch(`${apiBase}/chat/completions`, {
  method: "POST",
  headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
  body: JSON.stringify({ model, temperature, max_tokens: maxTokens, messages: [{ role: "user", content: prompt }] }),
});
if (!response.ok) {
  throw new Error(`model API returned HTTP ${response.status}`);
}
const payload = await response.json();
const content = payload.choices?.[0]?.message?.content;
if (typeof content !== "string") {
  throw new Error("model API response did not contain choices[0].message.content");
}
const jsonText = content.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();
const value = JSON.parse(jsonText);
const usage = payload.usage ?? {};
if (![usage.prompt_tokens, usage.completion_tokens, usage.total_tokens].every((item) => Number.isFinite(item))) {
  throw new Error("model API response did not contain complete token usage");
}
process.stdout.write(JSON.stringify({
  candidate: value.candidate ?? value,
  metadata: {
    provider: process.env.PURE_AUTO_CODEQL_M2_PROVIDER ?? "openai-compatible",
    model,
    adapter_version: "m2-openai-compatible/1",
    parameters: { temperature, output_limit: maxTokens },
    usage: {
      input_tokens: usage.prompt_tokens,
      output_tokens: usage.completion_tokens,
      total_tokens: usage.total_tokens,
    },
  },
}));
