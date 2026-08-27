const ANSI_PATTERN = /\u001b\[[0-?]*[ -\/]*[@-~]/g;

const SECRET_PATTERNS: readonly RegExp[] = [
  /(bearer\s+)[a-z0-9._~+\-/]+=*/gi,
  /((?:token|secret|password|api[_-]?key|authorization)\s*[:=]\s*)([^\s,;]+)/gi,
];

export function sanitizeOutput(value: string): string {
  let sanitized = value.replace(ANSI_PATTERN, "");
  for (const pattern of SECRET_PATTERNS) {
    sanitized = sanitized.replace(pattern, "$1[REDACTED]");
  }
  return sanitized;
}

export function limitOutput(value: string, maxBytes: number): { value: string; truncated: boolean } {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.byteLength <= maxBytes) {
    return { value, truncated: false };
  }
  return { value: bytes.subarray(0, maxBytes).toString("utf8"), truncated: true };
}
