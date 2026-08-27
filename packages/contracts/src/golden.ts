import { Type, type Static } from "typebox";

const NonEmptyString = Type.String({ minLength: 1 });

export const GoldenLocationSchema = Type.Object(
  {
    path: NonEmptyString,
    line: Type.Integer({ minimum: 1 }),
    semantic_id: Type.Optional(NonEmptyString),
  },
  { additionalProperties: false },
);
export type GoldenLocation = Static<typeof GoldenLocationSchema>;

export const GoldenExpectationSchema = Type.Object(
  {
    min_results: Type.Integer({ minimum: 0 }),
    max_results: Type.Integer({ minimum: 0 }),
    min_code_flows: Type.Integer({ minimum: 0 }),
    max_code_flows: Type.Integer({ minimum: 0 }),
    requires_code_flow: Type.Boolean(),
    rule_id: NonEmptyString,
    location: Type.Optional(GoldenLocationSchema),
    source: Type.Optional(GoldenLocationSchema),
    sink: Type.Optional(GoldenLocationSchema),
  },
  { additionalProperties: false },
);
export type GoldenExpectation = Static<typeof GoldenExpectationSchema>;

export const GoldenCaseSchema = Type.Object(
  {
    case_schema_version: Type.Literal("golden.case/v1"),
    case_id: Type.String({ pattern: "^[a-z0-9][a-z0-9_-]+$" }),
    fixture_root: NonEmptyString,
    language: NonEmptyString,
    cwe: Type.String({ pattern: "^CWE-[0-9]+$" }),
    vulnerability_category: NonEmptyString,
    description: NonEmptyString,
    source: Type.Object(
      {
        vulnerable: NonEmptyString,
        fixed: NonEmptyString,
        relationship: NonEmptyString,
      },
      { additionalProperties: false },
    ),
    build: Type.Object(
      {
        mode: Type.Union([Type.Literal("none"), Type.Literal("autobuild"), Type.Literal("manual")]),
        command: Type.Optional(NonEmptyString),
      },
      { additionalProperties: false },
    ),
    reference: Type.Object(
      {
        query: NonEmptyString,
        qlpack: NonEmptyString,
      },
      { additionalProperties: false },
    ),
    expected: Type.Object(
      {
        vulnerable: GoldenExpectationSchema,
        fixed: GoldenExpectationSchema,
      },
      { additionalProperties: false },
    ),
    timeout_seconds: Type.Integer({ minimum: 1 }),
    platforms: Type.Array(NonEmptyString, { minItems: 1 }),
    extractor_preconditions: Type.Array(NonEmptyString),
    provenance: Type.Object(
      {
        origin: NonEmptyString,
        license: NonEmptyString,
        attribution: NonEmptyString,
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);
export type GoldenCase = Static<typeof GoldenCaseSchema>;

export const GoldenManifestSchema = Type.Object(
  {
    manifest_schema_version: Type.Literal("golden.manifest/v1"),
    cases: Type.Array(GoldenCaseSchema, { minItems: 1 }),
  },
  { additionalProperties: false },
);
export type GoldenManifest = Static<typeof GoldenManifestSchema>;
