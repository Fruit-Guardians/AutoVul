import {
  CONTRACTS_VERSION,
  DomainError,
  parseSchema,
  TaintQueryIntentSchema,
  type LanguageFamily,
  type LanguageCapability,
  type TaintMatcher,
  type TaintFlowStep,
  type TaintFlowMode,
  type TaintQueryIntent,
} from "@pure-auto-codeql/contracts";

import { qlDoc, qlString } from "./ql-text.js";

export interface QueryLanguagePack {
  readonly language: LanguageFamily;
  readonly aliases: readonly string[];
  readonly extractor: string;
  readonly dependency: string;
  readonly capabilities: readonly LanguageCapability[];
  validateIntent(intent: TaintQueryIntent): void;
  renderProbe(intent: TaintQueryIntent, role: ProbeRole): string;
  renderPathQuery(queryId: string, intent: TaintQueryIntent): string;
  qlpackYml(): string;
}

export type ProbeRole = "source" | "sink";
type MatcherPosition = "endpoint" | "additional-from" | "additional-to";

const PYTHON: QueryLanguagePack = {
  language: "python",
  aliases: ["python"],
  extractor: "python",
  dependency: "codeql/python-all",
  capabilities: [
    capability("python-call", "python", "codeql/python-all", ["call", "call_argument", "function"], ["value", "taint"], "v2/test/m3-language-pack.test.ts"),
    capability("python-input", "python", "codeql/python-all", ["parameter", "environment"], ["value", "taint"], "v2/test/m3-language-pack.test.ts"),
  ],
  validateIntent(intent) {
    assertLanguage(intent, "python");
    assertMatcherKinds(intent, ["call", "call_argument", "function", "parameter", "environment"], "python");
  },
  renderProbe(intent, role) {
    return renderProbeQuery("python", intent, pythonMatcherExpression, role);
  },
  renderPathQuery(queryId, intent) {
    return renderPathQuery("python", queryId, intent, pythonImports(), pythonMatcherExpression, "TaintTracking");
  },
  qlpackYml: () => qlpack("codeql/python-all"),
};

const JAVASCRIPT: QueryLanguagePack = {
  language: "javascript",
  aliases: ["javascript", "typescript"],
  extractor: "javascript",
  dependency: "codeql/javascript-all",
  capabilities: [
    capability("javascript-call", "javascript", "codeql/javascript-all", ["call", "function", "constructor"], ["value", "taint"], "v2/test/m3-language-pack.test.ts"),
    capability("javascript-property", "javascript", "codeql/javascript-all", ["property", "environment", "parameter"], ["value", "taint"], "v2/test/m3-language-pack.test.ts"),
  ],
  validateIntent(intent) {
    if (intent.language !== "javascript" && intent.language !== "typescript") {
      throw new DomainError("INTENT_INVALID", "input", "JavaScript Language Pack requires javascript or typescript intent", false, {
        language: intent.language,
      });
    }
    assertMatcherKinds(intent, ["call", "function", "property", "environment", "parameter", "constructor"], "javascript");
  },
  renderProbe(intent, role) {
    return renderProbeQuery("javascript", intent, javascriptMatcherExpression, role);
  },
  renderPathQuery(queryId, intent) {
    return renderPathQuery("javascript", queryId, intent, javascriptImports(), javascriptMatcherExpression, intent.flow_mode === "taint" ? "TaintTracking" : "DataFlow");
  },
  qlpackYml: () => qlpack("codeql/javascript-all"),
};

const JAVA: QueryLanguagePack = {
  language: "java",
  aliases: ["java", "kotlin"],
  extractor: "java",
  dependency: "codeql/java-all",
  capabilities: [
    capability("java-call", "java", "codeql/java-all", ["call", "function", "constructor"], ["value", "taint"], "v2/test/m3-language-pack.test.ts"),
    capability("java-property", "java", "codeql/java-all", ["property"], ["value", "taint"], "v2/test/m3-language-pack.test.ts"),
    capability("java-input", "java", "codeql/java-all", ["environment", "parameter"], ["value", "taint"], "v2/test/m3-language-pack.test.ts"),
  ],
  validateIntent(intent) {
    if (intent.language !== "java" && intent.language !== "kotlin") {
      throw new DomainError("INTENT_INVALID", "input", "Java Language Pack requires java or kotlin intent", false, {
        language: intent.language,
      });
    }
    assertMatcherKinds(intent, ["call", "function", "constructor", "property", "environment", "parameter"], "java");
  },
  renderProbe(intent, role) {
    return renderProbeQuery("java", intent, javaMatcherExpression, role);
  },
  renderPathQuery(queryId, intent) {
    return renderPathQuery("java", queryId, intent, javaImports(), javaMatcherExpression, "TaintTracking");
  },
  qlpackYml: () => qlpack("codeql/java-all"),
};

const CPP: QueryLanguagePack = {
  language: "cpp",
  aliases: ["cpp", "c"],
  extractor: "cpp",
  dependency: "codeql/cpp-all",
  capabilities: [
    capability("cpp-call", "cpp", "codeql/cpp-all", ["call", "call_argument", "function"], ["value", "taint"], "v2/test/m3-language-pack.test.ts"),
    capability("cpp-memory", "cpp", "codeql/cpp-all", ["array_index", "array_element", "parameter", "property", "environment"], ["taint"], "v2/test/m3-language-pack.test.ts"),
  ],
  validateIntent(intent) {
    if (intent.language !== "cpp" && intent.language !== "c") {
      throw new DomainError("INTENT_INVALID", "input", "C/C++ Language Pack requires c or cpp intent", false, {
        language: intent.language,
      });
    }
    assertMatcherKinds(intent, ["call", "call_argument", "function", "array_index", "array_element", "parameter", "property", "environment"], "cpp");
  },
  renderProbe(intent, role) {
    return renderProbeQuery("cpp", intent, cppMatcherExpression, role);
  },
  renderPathQuery(queryId, intent) {
    return renderPathQuery("cpp", queryId, intent, cppImports(), cppMatcherExpression, "TaintTracking");
  },
  qlpackYml: () => qlpack("codeql/cpp-all"),
};

const PACKS: readonly QueryLanguagePack[] = [PYTHON, JAVASCRIPT, JAVA, CPP];

export function languagePackFor(language: string): QueryLanguagePack {
  const pack = PACKS.find((item) => item.language === language || item.aliases.includes(language));
  if (pack === undefined) {
    throw new DomainError("LANGUAGE_UNSUPPORTED", "input", `No M3 Language Pack is registered for ${language}`, false, {
      language,
      available: PACKS.map((item) => item.language),
    });
  }
  return pack;
}

export function allLanguagePacks(): readonly QueryLanguagePack[] {
  return PACKS;
}

export function normalizeTaintIntent(input: unknown, expectedLanguage?: string): TaintQueryIntent {
  const intent = parseSchema(TaintQueryIntentSchema, input, "taint query intent");
  const pack = languagePackFor(intent.language);
  if (expectedLanguage !== undefined && !pack.aliases.includes(expectedLanguage) && pack.language !== expectedLanguage) {
    throw new DomainError("INTENT_INVALID", "input", "Intent language does not match the workflow database language", false, {
      intentLanguage: intent.language,
      expectedLanguage,
    });
  }
  pack.validateIntent(intent);
  return intent;
}

export function renderTaintQuery(queryId: string, intent: TaintQueryIntent): string {
  const pack = languagePackFor(intent.language);
  pack.validateIntent(intent);
  return pack.renderPathQuery(queryId, intent);
}

export function renderTaintProbe(intent: TaintQueryIntent, role: ProbeRole = "source"): string {
  const pack = languagePackFor(intent.language);
  pack.validateIntent(intent);
  return pack.renderProbe(intent, role);
}

export function qlpackForLanguage(language: string): string {
  return languagePackFor(language).qlpackYml();
}

function renderPathQuery(
  family: string,
  queryId: string,
  intent: TaintQueryIntent,
  imports: string,
  matcher: (role: "source" | "sink", value: string, item: TaintMatcher, position?: MatcherPosition) => string,
  flowNamespace: "DataFlow" | "TaintTracking",
): string {
  const description = qlDoc(intent.description ?? intent.message);
  const tags = `security external/cwe/${intent.cwe.toLowerCase().replaceAll("_", "-")}`;
  const source = matcher("source", "source", intent.source);
  const sink = matcher("sink", "sink", intent.sink);
  const additionalSteps: readonly TaintFlowStep[] = [
    ...(intent.additional_flow_steps ?? []),
    ...(intent.additional_flow ?? []).map((step) => ({ from: step, to: step })),
  ];
  const additional = additionalSteps.length === 0
    ? ""
    : `\n\n  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {\n${additionalSteps.map((step) => `    ${matcher("source", "node1", step.from, "additional-from")}${additionalFlowGuard(family, "node1", step.from, intent)} and ${matcher("sink", "node2", step.to, "additional-to")}`).join("\n    or\n")}\n  }`;
  const sanitizer = intent.sanitizer?.length === 0 || intent.sanitizer === undefined
    ? ""
    : `\n\n  predicate isBarrier(DataFlow::Node node) {\n${intent.sanitizer.map((step) => `    ${matcher("source", "node", step)}`).join("\n    or\n")}\n  }`;
  return [
    "/**",
    ` * @name ${description}`,
    ` * @description ${description}`,
    " * @kind path-problem",
    " * @problem.severity warning",
    " * @security-severity 7.5",
    " * @precision high",
    ` * @id pure-auto-codeql/${safeId(queryId)}`,
    ` * @tags ${tags}`,
    " */",
    "",
    imports,
    "",
    "module Config implements DataFlow::ConfigSig {",
    "  predicate isSource(DataFlow::Node source) {",
    `    ${source}`,
    "  }",
    "",
    "  predicate isSink(DataFlow::Node sink) {",
    `    ${sink}`,
    `  }${additional}${sanitizer}`,
    "}",
    "",
    `module Flow = ${flowNamespace}::Global<Config>;`,
    "import Flow::PathGraph",
    "",
    "from Flow::PathNode source, Flow::PathNode sink",
    "where Flow::flowPath(source, sink)",
    `select sink.getNode(), source, sink, "${qlString(intent.message)}"`,
    "",
  ].join("\n");
}

function renderProbeQuery(
  family: string,
  intent: TaintQueryIntent,
  matcher: (role: "source" | "sink", value: string, item: TaintMatcher, position?: MatcherPosition) => string,
  role: ProbeRole,
): string {
  const imports = family === "python" ? pythonImports() : family === "javascript" ? javascriptImports() : family === "java" ? javaImports() : cppImports();
  const selected = role === "source" ? intent.source : intent.sink;
  const ruleId = `pure-auto-codeql/probe-${family}-${role}`;
  return [
    "/**",
    ` * @name M3 ${family} ${role} probe`,
    ` * @description Probe the ${role} matcher before synthesis.`,
    " * @kind problem",
    " * @problem.severity recommendation",
    ` * @id ${ruleId}`,
    " */",
    "",
    imports,
    "",
    "from DataFlow::Node node",
    `where ${matcher(role, "node", selected)}`,
    `select node, "M3 ${role} probe"`,
    "",
  ].join("\n");
}

function pythonImports(): string {
  return ["import python", "import semmle.python.dataflow.new.DataFlow", "import semmle.python.dataflow.new.TaintTracking", "import semmle.python.ApiGraphs"].join("\n");
}

function javascriptImports(): string {
  return ["import javascript", "import semmle.javascript.dataflow.DataFlow", "import semmle.javascript.dataflow.TaintTracking"].join("\n");
}

function javaImports(): string {
  return ["import java", "import semmle.code.java.dataflow.DataFlow", "import semmle.code.java.dataflow.TaintTracking"].join("\n");
}

function cppImports(): string {
  return ["import cpp", "import semmle.code.cpp.dataflow.new.DataFlow", "import semmle.code.cpp.dataflow.new.TaintTracking"].join("\n");
}

function pythonMatcherExpression(role: "source" | "sink", value: string, matcher: TaintMatcher, position: MatcherPosition = "endpoint"): string {
  if (matcher.kind === "environment") {
    const member = matcher.name ?? "getenv";
    return `${value} = API::moduleImport("os").getMember("${qlString(member)}").getACall()`;
  }
  if (matcher.kind === "call" || matcher.kind === "call_argument" || matcher.kind === "function") {
    const member = matcher.member ?? matcher.name;
    if (member === undefined) {
      throw new DomainError("CAPABILITY_MISMATCH", "input", "Python call matcher requires member or name", false, { role, matcher });
    }
    if (matcher.file !== undefined || matcher.symbol !== undefined || matcher.line !== undefined) {
      const constraints = [
        pythonConcreteCallIdentity("call", matcher.module, member),
        pythonCallLocationConstraint(matcher, role, position),
      ].filter((item) => item.length > 0);
      const selected = matcher.kind === "call_argument" || (role === "sink" && position === "endpoint")
        ? pythonArgument("call", matcher)
        : "call";
      return `exists(DataFlow::CallCfgNode call | ${constraints.join(" and ")} and ${value} = ${selected})`;
    }
    const module = matcher.module ?? "builtins";
    const call = `API::moduleImport("${qlString(module)}").getMember("${qlString(member)}").getACall()`;
    const keywordConstraint = pythonKeywordConstraint("call", matcher);
    const locationConstraint = pythonCallLocationConstraint(matcher, role, position);
    const callConstraints = [
      `call = ${call}`,
      keywordConstraint,
      locationConstraint,
    ].filter((item) => item.length > 0);
    const selected = matcher.kind === "call_argument" || (role === "sink" && position === "endpoint")
      ? pythonArgument("call", matcher)
      : "call";
    return callConstraints.length === 1 && selected === "call"
      ? `${value} = ${call}`
      : `exists(DataFlow::CallCfgNode call | ${callConstraints.join(" and ")} and ${value} = ${selected})`;
  }
  if (matcher.kind === "parameter") {
    const parameter = "parameter.getParameter()";
    const constraints = [
      matcher.name === undefined ? "" : `${parameter}.getName() = "${qlString(matcher.name)}"`,
      matcher.file === undefined ? "" : `${parameter}.getLocation().getFile().${matcher.file.startsWith("/") ? "getAbsolutePath()" : "getRelativePath()"} = "${qlString(matcher.file.replaceAll("\\", "/"))}"`,
      matcher.line === undefined ? "" : `${parameter}.getLocation().getStartLine() = ${matcher.line}`,
      matcher.symbol === undefined ? "" : `exists(Function enclosingFunction | (enclosingFunction.getArg(_) = ${parameter} or enclosingFunction.getVararg() = ${parameter} or enclosingFunction.getKwarg() = ${parameter} or enclosingFunction.getAKeywordOnlyArg() = ${parameter}) and (enclosingFunction.getName() = "${qlString(matcher.symbol.split(".").at(-1) ?? matcher.symbol)}" or enclosingFunction.getName().matches("%.${qlString(matcher.symbol.split(".").at(-1) ?? matcher.symbol)}")))`,
    ].filter((item) => item.length > 0);
    return `exists(DataFlow::ParameterNode parameter | ${value} = parameter${constraints.length === 0 ? "" : ` and ${constraints.join(" and ")}`})`;
  }
  throw new DomainError("CAPABILITY_MISMATCH", "input", `Python matcher kind ${matcher.kind} is not implemented`, false, { role, matcher });
}

function pythonCallLocationConstraint(matcher: TaintMatcher, role: "source" | "sink", position: MatcherPosition = "endpoint"): string {
  const location = matcher.kind === "call_argument" || (role === "sink" && position === "endpoint")
    ? `${pythonArgument("call", matcher)}.getLocation()`
    : "call.getLocation()";
  const constraints = [
    matcher.file === undefined ? "" : `${location}.getFile().${matcher.file.startsWith("/") ? "getAbsolutePath()" : "getRelativePath()"} = "${qlString(matcher.file.replaceAll("\\", "/"))}"`,
    matcher.symbol === undefined ? "" : `call.getScope().(Function).getName() = "${qlString(matcher.symbol.split(".").at(-1) ?? matcher.symbol)}"`,
    matcher.line === undefined ? "" : `${location}.getStartLine() = ${matcher.line}`,
  ].filter((item) => item.length > 0);
  return constraints.join(" and ");
}

function pythonLocalCallNameConstraint(call: string, name: string): string {
  const functionNode = `${call}.getNode().(CallNode).getFunction().getNode()`;
  return `(${functionNode}.(Name).getId() = "${qlString(name)}" or ${functionNode}.(Attribute).getAttr() = "${qlString(name)}")`;
}

function pythonConcreteCallIdentity(call: string, module: string | undefined, member: string): string {
  const local = pythonLocalCallNameConstraint(call, member);
  if (module === undefined) return local;
  const api = `${call} = API::moduleImport("${qlString(module)}").getMember("${qlString(member)}").getACall()`;
  return `(${local} or ${api})`;
}

function pythonKeywordConstraint(call: string, matcher: TaintMatcher): string {
  if (matcher.keyword_name === undefined) {
    return "";
  }
  const keyword = `${call}.getArgByName("${qlString(matcher.keyword_name)}").asExpr()`;
  if (matcher.keyword_value === undefined) {
    return `${keyword} instanceof Keyword`;
  }
  if (typeof matcher.keyword_value === "boolean") {
    return `${keyword} instanceof BooleanLiteral and ${keyword}.(BooleanLiteral).booleanValue() = ${matcher.keyword_value ? "true" : "false"}`;
  }
  if (typeof matcher.keyword_value === "string") {
    return `${keyword} instanceof StringLiteral and ${keyword}.(StringLiteral).getText() = "${qlString(matcher.keyword_value)}"`;
  }
  if (Number.isInteger(matcher.keyword_value)) {
    return `${keyword} instanceof IntegerLiteral and ${keyword}.(IntegerLiteral).getValue() = ${matcher.keyword_value}`;
  }
  throw new DomainError("CAPABILITY_MISMATCH", "input", "Python keyword matcher only supports boolean, string, or integer literals", false, {
    role: "sink",
    matcher,
  });
}

function javascriptMatcherExpression(role: "source" | "sink", value: string, matcher: TaintMatcher, position: MatcherPosition = "endpoint"): string {
  if (matcher.kind === "environment" || matcher.kind === "property") {
    if (matcher.kind === "property" && matcher.module === undefined && (matcher.file !== undefined || matcher.symbol !== undefined || matcher.line !== undefined)) {
      const property = matcher.property ?? matcher.name;
      if (property !== undefined) {
        const localProperty = "localProperty";
        const constraints = [`${localProperty}.getPropertyName() = "${qlString(property)}"`];
        if (matcher.file !== undefined) {
          const fileAccessor = matcher.file.startsWith("/") ? "getAbsolutePath()" : "getRelativePath()";
          constraints.push(`${localProperty}.getFile().${fileAccessor} = "${qlString(matcher.file.replaceAll("\\", "/"))}"`);
        }
        if (matcher.line !== undefined) {
          constraints.push(`${localProperty}.getLocation().getStartLine() = ${matcher.line}`);
        }
        return `exists(DataFlow::PropRead ${localProperty} | ${constraints.join(" and ")} and ${value} = ${localProperty})`;
      }
    }
    const base = matcher.module ?? matcher.type ?? "process";
    const property = matcher.property ?? matcher.name ?? "env";
    const reads = property.split(".").filter((item) => item.length > 0).map((item) => `.getAPropertyRead("${qlString(item)}")`).join("");
    return `${value} = DataFlow::globalVarRef("${qlString(base)}")${reads}`;
  }
  if (matcher.kind === "call" || matcher.kind === "function" || matcher.kind === "constructor") {
    if (matcher.file !== undefined || matcher.symbol !== undefined || matcher.line !== undefined) {
      const name = matcher.member ?? matcher.name;
      if (name !== undefined) {
        const localCall = "localCall";
        const constraints = [`${localCall}.getCalleeName() = "${qlString(name)}"`];
        if (matcher.file !== undefined) {
          const fileAccessor = matcher.file.startsWith("/") ? "getAbsolutePath()" : "getRelativePath()";
          constraints.push(`${localCall}.getFile().${fileAccessor} = "${qlString(matcher.file.replaceAll("\\", "/"))}"`);
        }
        if (matcher.symbol !== undefined) {
          const symbol = matcher.symbol.split(".").at(-1) ?? matcher.symbol;
          constraints.push(`(${localCall}.getEnclosingFunction().getName() = "${qlString(symbol)}" or ${localCall}.getEnclosingFunction().getName().matches("%.${qlString(symbol)}"))`);
        }
        if (matcher.line !== undefined) {
          constraints.push(`${localCall}.getLocation().getStartLine() = ${matcher.line}`);
        }
        const selected = role === "source" || position !== "endpoint" ? "localCall" : `localCall.getArgument(${matcher.argument_index ?? 0})`;
        // At a concrete source location, the AST call is authoritative. This also
        // handles aliased imports such as `const exec = require(...).exec`, for
        // which moduleImport(...).getAMemberCall(...) does not resolve the local
        // call node even though the unscoped API probe does.
        return `exists(CallExpr ${localCall} | ${constraints.join(" and ")} and ${value}.asExpr() = ${selected})`;
      }
    }
    const callee = matcher.module === undefined
      ? `DataFlow::globalVarRef("${qlString(matcher.type ?? matcher.name ?? "Function")}")`
      : `DataFlow::moduleImport("${qlString(matcher.module)}")`;
    const member = matcher.member ?? matcher.name;
    const call = member === undefined ? `${callee}.getACall()` : `${callee}.getAMemberCall("${qlString(member)}")`;
    return role === "source" || position !== "endpoint" ? `${value} = ${call}` : `${value} = ${call}.getArgument(${matcher.argument_index ?? 0})`;
  }
  if (matcher.kind === "parameter") {
    const parameter = "parameter.getParameter()";
    const constraints = [
      matcher.name === undefined ? undefined : `parameter.getName() = "${qlString(matcher.name)}"`,
      matcher.file === undefined ? undefined : `${parameter}.getFile().${matcher.file.startsWith("/") ? "getAbsolutePath()" : "getRelativePath()"} = "${qlString(matcher.file.replaceAll("\\", "/"))}"`,
      matcher.line === undefined ? undefined : `${parameter}.getLocation().getStartLine() = ${matcher.line}`,
      matcher.symbol === undefined ? undefined : `exists(Function enclosingFunction | enclosingFunction.getAParameter() = ${parameter} and (enclosingFunction.getName() = "${qlString(matcher.symbol.split(".").at(-1) ?? matcher.symbol)}" or enclosingFunction.getName().matches("%.${qlString(matcher.symbol.split(".").at(-1) ?? matcher.symbol)}")))`,
    ].filter((item): item is string => item !== undefined);
    return `exists(DataFlow::ParameterNode parameter | ${value} = parameter${constraints.length === 0 ? "" : ` and ${constraints.join(" and ")}`})`;
  }
  throw new DomainError("CAPABILITY_MISMATCH", "input", `JavaScript matcher kind ${matcher.kind} is not implemented`, false, { role, matcher });
}

function javaMatcherExpression(role: "source" | "sink", value: string, matcher: TaintMatcher, position: MatcherPosition = "endpoint"): string {
  if (matcher.kind === "environment" || matcher.kind === "call" || matcher.kind === "function") {
    const name = matcher.name ?? matcher.member ?? "getenv";
    const declaringType = matcher.type === undefined ? "" : ` and call.getMethod().getDeclaringType().hasQualifiedName("${qlString(matcher.type.split(".").slice(0, -1).join("."))}", "${qlString(matcher.type.split(".").at(-1) ?? matcher.type)}")`;
    const returnsCall = role === "source" || position !== "endpoint";
    const call = `exists(MethodCall call | ${returnsCall ? `${value}.asExpr() = call` : `${value}.asExpr() = call.getArgument(${matcher.argument_index ?? 0})`} and call.getMethod().hasName("${qlString(name)}")${declaringType})`;
    return call;
  }
  if (matcher.kind === "constructor") {
    const typeName = matcher.type ?? "java.io.File";
    const parts = typeName.split(".");
    const simple = parts.pop() ?? typeName;
    const pkg = parts.join(".");
    const returnsCall = role === "source" || position !== "endpoint";
    return `exists(ConstructorCall call | call.getConstructedType().hasQualifiedName("${qlString(pkg)}", "${qlString(simple)}") and ${value}.asExpr() = ${returnsCall ? "call" : `call.getArgument(${matcher.argument_index ?? 0})`})`;
  }
  if (matcher.kind === "parameter") {
    return `exists(Parameter parameter | ${value}.asExpr() = parameter.getAnAccess()${matcher.name === undefined ? "" : ` and parameter.getName() = "${qlString(matcher.name)}"`})`;
  }
  if (matcher.kind === "property") {
    const property = matcher.property ?? matcher.name;
    if (property === undefined) {
      throw new DomainError("CAPABILITY_MISMATCH", "input", "Java property matcher requires property or name", false, { role, matcher });
    }
    const field = matcher.type === undefined
      ? `read.getField().hasName("${qlString(property)}")`
      : `read.getField().hasQualifiedName("${qlString(javaPackage(matcher.type))}", "${qlString(javaSimpleType(matcher.type))}", "${qlString(property)}")`;
    return `exists(FieldRead read | ${field} and ${value}.asExpr() = read)`;
  }
  throw new DomainError("CAPABILITY_MISMATCH", "input", `Java matcher kind ${matcher.kind} is not implemented`, false, { role, matcher });
}

function additionalFlowGuard(family: string, value: string, matcher: TaintMatcher, intent: TaintQueryIntent): string {
  if (family !== "java" || matcher.kind !== "parameter") return "";
  const sanitizers = (intent.sanitizer ?? []).filter((item) => item.kind === "call" || item.kind === "function" || item.kind === "environment");
  return sanitizers.map((sanitizer) => ` and not exists(MethodCall clean | ${javaCallConstraint("clean", sanitizer)} and clean.getArgument(${sanitizer.argument_index ?? 0}) = ${value}.asExpr())`).join("");
}

function javaCallConstraint(value: string, matcher: TaintMatcher): string {
  const name = matcher.name ?? matcher.member;
  if (name === undefined) {
    throw new DomainError("CAPABILITY_MISMATCH", "input", "Java call matcher requires name or member", false, { matcher });
  }
  const declaringType = matcher.type === undefined ? "" : ` and ${value}.getMethod().getDeclaringType().hasQualifiedName("${qlString(javaPackage(matcher.type))}", "${qlString(javaSimpleType(matcher.type))}")`;
  return `${value}.getMethod().hasName("${qlString(name)}")${declaringType}`;
}

function javaPackage(typeName: string): string {
  return typeName.split(".").slice(0, -1).join(".");
}

function javaSimpleType(typeName: string): string {
  return typeName.split(".").at(-1) ?? typeName;
}

function cppMatcherExpression(role: "source" | "sink", value: string, matcher: TaintMatcher, position: MatcherPosition = "endpoint"): string {
  if (matcher.kind === "array_index") {
    const constraints = cppArrayIndexLocationConstraints(matcher);
    return `exists(ArrayExpr access | ${constraints.length === 0 ? "" : `${constraints.join(" and ")} and `}${value}.asExpr() = access.getArrayOffset())`;
  }
  if (matcher.kind === "array_element") {
    const constraints = cppArrayIndexLocationConstraints(matcher);
    return `exists(ArrayExpr access | ${constraints.length === 0 ? "" : `${constraints.join(" and ")} and `}${value}.asExpr() = access)`;
  }
  if (matcher.kind === "function" || matcher.kind === "call" || matcher.kind === "call_argument" || matcher.kind === "environment") {
    const name = matcher.name ?? matcher.member;
    if (name === undefined) {
      throw new DomainError("CAPABILITY_MISMATCH", "input", "C/C++ function matcher requires name or member", false, { role, matcher });
    }
    const target = cppFunctionTargetConstraint("call.getTarget()", name);
    const selected = role === "source" || (position !== "endpoint" && matcher.kind !== "call_argument")
      ? "call"
      : `call.getArgument(${matcher.argument_index ?? 0})`;
    // C/C++ CodeQL can select the argument expression as the data-flow node, but
    // its stable source/file location for a constrained call is the enclosing
    // FunctionCall.  Constraining the argument expression's location makes an
    // otherwise valid direct flow disappear on real databases (for example a
    // field read flowing into strcpy's second argument).  Keep argument
    // selection semantic while anchoring endpoint identity to the call site.
    const locationTarget = position === "endpoint" ? "call" : (matcher.kind === "call_argument" ? selected : "call");
    const constraints = [target, ...cppCallLocationConstraints(matcher, locationTarget)].join(" and ");
    const call = `exists(FunctionCall call | ${constraints} and ${value}.asExpr() = ${selected})`;
    return call;
  }
  if (matcher.kind === "parameter") {
    const constraints = [
      matcher.name === undefined ? undefined : `parameter.getName() = "${qlString(matcher.name)}"`,
      matcher.file === undefined ? undefined : `parameter.getFile().${matcher.file.startsWith("/") ? "getAbsolutePath()" : "getRelativePath()"} = "${qlString(matcher.file.replaceAll("\\", "/"))}"`,
      matcher.line === undefined ? undefined : `parameter.getLocation().getStartLine() = ${matcher.line}`,
      matcher.symbol === undefined ? undefined : `parameter.getFunction().getName() = "${qlString(matcher.symbol)}"`,
    ].filter((item): item is string => item !== undefined);
    const constraintText = constraints.length === 0 ? "" : ` and ${constraints.join(" and ")}`;
    return `(exists(Parameter parameter | ${value}.asParameter() = parameter${constraintText}) or exists(Parameter parameter, VariableAccess access | access.getTarget() = parameter and ${value}.asExpr() = access${constraintText}))`;
  }
  if (matcher.kind === "property") {
    const property = matcher.property ?? matcher.name ?? matcher.member;
    if (property === undefined) {
      throw new DomainError("CAPABILITY_MISMATCH", "input", "C/C++ property matcher requires property, name, or member", false, { role, matcher });
    }
    const constraints = [`access.getTarget().getName() = "${qlString(property)}"`];
    if (matcher.type !== undefined) {
      constraints.push(cppFieldTypeConstraint(matcher.type, property));
    }
    if (matcher.file !== undefined) {
      const accessor = matcher.file.startsWith("/") ? "getAbsolutePath()" : "getRelativePath()";
      constraints.push(`access.getFile().${accessor} = "${qlString(matcher.file.replaceAll("\\", "/"))}"`);
    }
    if (matcher.symbol !== undefined) {
      constraints.push(`access.getEnclosingFunction().getName() = "${qlString(matcher.symbol)}"`);
    }
    if (matcher.line !== undefined) {
      constraints.push(`access.getLocation().getStartLine() = ${matcher.line}`);
    }
    return `exists(FieldAccess access | ${constraints.join(" and ")} and ${value}.asExpr() = access)`;
  }
  throw new DomainError("CAPABILITY_MISMATCH", "input", `C/C++ matcher kind ${matcher.kind} is not implemented`, false, { role, matcher });
}

function cppFieldTypeConstraint(typeName: string, property: string): string {
  const declaringType = `access.getTarget().getDeclaringType()`;
  return `(${declaringType}.getName() = "${qlString(typeName)}" or ${declaringType}.getQualifiedName() = "${qlString(typeName)}")`;
}

function cppArrayIndexLocationConstraints(matcher: TaintMatcher): string[] {
  const constraints: string[] = [];
  if (matcher.file !== undefined) {
    const accessor = matcher.file.startsWith("/") ? "getAbsolutePath()" : "getRelativePath()";
    constraints.push(`access.getFile().${accessor} = "${qlString(matcher.file.replaceAll("\\", "/"))}"`);
  }
  if (matcher.symbol !== undefined) {
    constraints.push(`access.getEnclosingFunction().getName() = "${qlString(matcher.symbol)}"`);
  }
  if (matcher.line !== undefined) {
    constraints.push(`access.getLocation().getStartLine() = ${matcher.line}`);
  }
  return constraints;
}

function cppFunctionTargetConstraint(target: string, name: string): string {
  const fortified = new Map([
    ["strcpy", "__builtin___strcpy_chk"],
    ["strncpy", "__builtin___strncpy_chk"],
    ["strcat", "__builtin___strcat_chk"],
    ["strncat", "__builtin___strncat_chk"],
    ["memcpy", "__builtin___memcpy_chk"],
    ["memmove", "__builtin___memmove_chk"],
    ["memset", "__builtin___memset_chk"],
  ]).get(name);
  return fortified === undefined
    ? `${target}.hasGlobalName("${qlString(name)}")`
    : `(${target}.hasGlobalName("${qlString(name)}") or ${target}.hasGlobalName("${qlString(fortified)}"))`;
}

function cppCallLocationConstraints(matcher: TaintMatcher, selected: string = "call"): string[] {
  const constraints: string[] = [];
  const location = selected === "call" ? "call.getLocation()" : `${selected}.getLocation()`;
  if (matcher.file !== undefined) {
    const accessor = matcher.file.startsWith("/") ? "getAbsolutePath()" : "getRelativePath()";
    const file = selected === "call" ? "call.getFile()" : `${selected}.getFile()`;
    constraints.push(`${file}.${accessor} = "${qlString(matcher.file.replaceAll("\\", "/"))}"`);
  }
  if (matcher.symbol !== undefined) {
    constraints.push(`call.getEnclosingFunction().getName() = "${qlString(matcher.symbol)}"`);
  }
  if (matcher.line !== undefined) {
    constraints.push(`${location}.getStartLine() = ${matcher.line}`);
  }
  return constraints;
}

function pythonArgument(call: string, matcher: TaintMatcher): string {
  if (matcher.argument_name !== undefined) return `${call}.getArgByName("${qlString(matcher.argument_name)}")`;
  return `${call}.getArg(${matcher.argument_index ?? 0})`;
}

function assertLanguage(intent: TaintQueryIntent, expected: LanguageFamily): void {
  if (intent.language !== expected) {
    throw new DomainError("INTENT_INVALID", "input", `Expected ${expected} intent`, false, { language: intent.language });
  }
}

function assertMatcherKinds(intent: TaintQueryIntent, supported: readonly string[], pack: string): void {
  for (const [role, matcher] of [["source", intent.source], ["sink", intent.sink]] as const) {
    if (!supported.includes(matcher.kind)) {
      throw new DomainError("CAPABILITY_MISMATCH", "input", `${pack} Language Pack does not support ${matcher.kind} ${role} matcher`, false, {
        role,
        kind: matcher.kind,
        supported,
      });
    }
  }
}

function qlpack(dependency: string): string {
  return `name: pure-auto-codeql/generated\nversion: 0.0.1\ndependencies:\n  ${dependency}: "*"\n`;
}

function capability(
  capabilityId: string,
  language: LanguageFamily,
  dependency: string,
  matcherKinds: readonly string[],
  flowModes: readonly TaintFlowMode[],
  fixture: string,
): LanguageCapability {
  return {
    schema_version: CONTRACTS_VERSION,
    capability_id: capabilityId,
    language,
    pack_dependency: dependency,
    pack_version_range: "verified-local-2.26.1",
    matcher_kinds: [...matcherKinds],
    flow_modes: [...flowModes],
    verified_at: "2026-08-24T00:00:00.000Z",
    positive_fixture: fixture,
    provenance: "PureAutoCodeQL M3 renderer compile gate",
  };
}

function safeId(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._/-]+/g, "-").replace(/\/+$/g, "");
}
