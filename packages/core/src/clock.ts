import type { ClockPort, IdGeneratorPort } from "./ports.js";
import type { RunId } from "@autovul/contracts";

export class SystemClock implements ClockPort {
  now(): string {
    return new Date().toISOString();
  }
}

export class RandomIdGenerator implements IdGeneratorPort {
  next(): RunId {
    const suffix = `${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 12)}`;
    return `run_${suffix}`;
  }
}
