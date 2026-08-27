import { Value } from "typebox/value";
import type { Static, TSchema } from "typebox";

import { DomainError } from "./errors.js";

export function parseSchema<TSchemaType extends TSchema>(schema: TSchemaType, input: unknown, label: string): Static<TSchemaType> {
  if (!Value.Check(schema, input)) {
    const issues = [...Value.Errors(schema, input)].map((issue) => ({
      path: "path" in issue && typeof issue.path === "string" ? issue.path : "",
      message: issue.message,
    }));
    throw new DomainError("INVALID_INPUT", "input", `Invalid ${label}`, false, { label, issues });
  }
  return input as Static<TSchemaType>;
}
