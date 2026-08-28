import type { CodeqlEnvironment, DatabaseManifest } from "@autovul/contracts";

import type { CodeqlOperationOptions, CodeqlPort } from "./ports.js";

export class DoctorService {
  constructor(private readonly codeql: CodeqlPort) {}

  doctor(options: CodeqlOperationOptions): Promise<CodeqlEnvironment> {
    return this.codeql.doctor(options);
  }

  inspectDatabase(path: string, options: CodeqlOperationOptions): Promise<DatabaseManifest> {
    return this.codeql.inspectDatabase(path, options);
  }

  validateDatabase(path: string, options: CodeqlOperationOptions): Promise<DatabaseManifest> {
    return this.codeql.validateDatabase(path, options);
  }
}
