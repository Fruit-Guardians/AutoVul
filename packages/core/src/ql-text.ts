/** Escapes free-form text for a QL metadata/doc comment. */
export function qlDoc(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replaceAll("\n", " ")
    .replaceAll("*/", "* /");
}

/** Escapes a plain string literal embedded in generated QL. */
export function qlString(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replaceAll('"', '\\"')
    .replaceAll("\n", " ");
}
