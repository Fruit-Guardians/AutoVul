/** A deterministic, non-secret content fingerprint for workflow artifacts. */
export function stableDigest(value: string): string {
  let first = 0xcbf29ce4;
  let second = 0x9e3779b9;
  for (let index = 0; index < value.length; index += 1) {
    first ^= value.charCodeAt(index);
    first = Math.imul(first, 0x01000193);
    const reverse = value.length - index - 1;
    second ^= value.charCodeAt(reverse);
    second = Math.imul(second, 0x85ebca6b);
  }
  return `${(first >>> 0).toString(16).padStart(8, "0")}${(second >>> 0).toString(16).padStart(8, "0")}`;
}
