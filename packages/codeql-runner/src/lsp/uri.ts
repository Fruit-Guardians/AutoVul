import { pathToFileURL } from "node:url";

export function lspUriForPath(path: string): string {
  return pathToFileURL(path).href;
}
