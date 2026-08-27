import {
  access,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  rmdir,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, join } from "node:path";
import { randomUUID } from "node:crypto";

import { DomainError } from "@pure-auto-codeql/contracts";
import type { FileLock, FileSystemPort } from "@pure-auto-codeql/core";

export class NodeFileSystemPort implements FileSystemPort {
  constructor(private readonly options: { readonly lockStaleMs?: number } = {}) {}

  async ensureDirectory(path: string): Promise<void> {
    await mkdir(path, { recursive: true });
  }

  async readText(path: string): Promise<string> {
    return readFile(path, "utf8");
  }

  async writeTextAtomic(path: string, content: string): Promise<void> {
    await this.ensureDirectory(dirname(path));
    const temporary = `${path}.tmp-${randomUUID()}`;
    try {
      await writeFile(temporary, content, { encoding: "utf8", mode: 0o600, flag: "wx" });
      await rename(temporary, path);
    } finally {
      await unlink(temporary).catch((error: unknown) => {
        if (!isNotFound(error)) {
          throw error;
        }
      });
    }
  }

  async exists(path: string): Promise<boolean> {
    try {
      await access(path, constants.F_OK);
      return true;
    } catch {
      return false;
    }
  }

  async stat(path: string): Promise<{ exists: boolean; isDirectory: boolean; modifiedAtMs?: number }> {
    try {
      const result = await stat(path);
      return { exists: true, isDirectory: result.isDirectory(), modifiedAtMs: result.mtimeMs };
    } catch {
      return { exists: false, isDirectory: false };
    }
  }

  async remove(path: string): Promise<void> {
    await rm(path, { force: true });
  }

  async canonicalize(path: string): Promise<string> {
    return realpath(path);
  }

  async acquireLock(path: string): Promise<FileLock> {
    await this.ensureDirectory(dirname(path));
    const staleAfterMs = this.options.lockStaleMs ?? 10 * 60 * 1000;
    const ownerToken = randomUUID();
    const ownerPath = join(path, `${LOCK_OWNER_PREFIX}${ownerToken}`);
    for (;;) {
      let createdDirectory = false;
      try {
        await mkdir(path, { recursive: false, mode: 0o700 });
        createdDirectory = true;
        await writeFile(
          ownerPath,
          JSON.stringify({ ownerToken, pid: process.pid, createdAt: new Date().toISOString() }),
          { encoding: "utf8", flag: "wx", mode: 0o600 },
        );
        return lockFor(ownerPath, path, ownerToken);
      } catch (error: unknown) {
        if (createdDirectory) {
          await rmdir(path).catch(() => undefined);
        }
        if (!isAlreadyExists(error)) {
          throw error;
        }

        const existing = await inspectLock(path);
        if (existing === undefined) {
          continue;
        }
        if (!reclaimable(existing, staleAfterMs)) {
          throw runLocked(path, existing);
        }

        // A legacy regular-file lock does not carry an exact owner-token path.
        // A recovery gate serializes all new-format contenders before the
        // legacy path is atomically moved. This keeps compatibility without
        // reintroducing a check-then-delete race.
        if (!existing.isDirectory) {
          await this.recoverLegacyLock(path, existing, staleAfterMs);
          continue;
        }

        // The lock directory itself is never renamed. We only rename an
        // exact entry observed in that directory. A contender that inspected
        // owner A cannot later remove owner B because B has a different
        // owner-token filename. The final rmdir is atomic and succeeds only
        // if no new owner has filled the directory in the meantime.
        if (existing.removablePath !== undefined) {
          const tombstone = `${existing.removablePath}.stale-${randomUUID()}`;
          try {
            await rename(existing.removablePath, tombstone);
          } catch (renameError: unknown) {
            if (isNotFound(renameError) || isAlreadyExists(renameError) || isConcurrentRenameRace(renameError)) {
              continue;
            }
            throw renameError;
          }
          await rm(tombstone, { recursive: true, force: true }).catch((cleanupError: unknown) => {
            if (!isNotFound(cleanupError)) {
              throw cleanupError;
            }
          });
        }

        try {
          await rmdir(path);
        } catch (removeError: unknown) {
          if (isNotFound(removeError) || isDirectoryNotEmpty(removeError)) {
            continue;
          }
          throw removeError;
        }
      }
    }
  }

  private async recoverLegacyLock(path: string, observed: ExistingLock, staleAfterMs: number): Promise<void> {
    let recoveryGate: FileLock;
    try {
      recoveryGate = await this.acquireLock(`${path}.legacy-recovery`);
    } catch (error: unknown) {
      if (error instanceof DomainError && error.code === "RUN_LOCKED") {
        throw runLocked(path, observed, { legacyRecoveryLocked: true });
      }
      throw error;
    }

    try {
      const current = await inspectLock(path);
      if (current === undefined || current.isDirectory || !reclaimable(current, staleAfterMs)) {
        return;
      }
      const tombstone = `${path}.stale-${randomUUID()}`;
      try {
        await rename(path, tombstone);
      } catch (renameError: unknown) {
        if (isNotFound(renameError) || isAlreadyExists(renameError) || isConcurrentRenameRace(renameError)) {
          return;
        }
        throw renameError;
      }
      await rm(tombstone, { recursive: true, force: true }).catch((cleanupError: unknown) => {
        if (!isNotFound(cleanupError)) {
          throw cleanupError;
        }
      });
    } finally {
      await recoveryGate.release();
    }
  }
}

const LOCK_OWNER_PREFIX = ".owner-";

interface LockMetadata {
  readonly ownerToken?: string;
  readonly pid?: number;
  readonly createdAt?: string;
}

interface ExistingLock {
  readonly metadata: LockMetadata;
  readonly ownerRecords: readonly LockMetadata[];
  readonly isDirectory: boolean;
  readonly removablePath?: string;
  readonly modifiedAtMs: number;
}

function lockFor(ownerPath: string, lockPath: string, ownerToken: string): FileLock {
  let released = false;
  return {
    release: async (): Promise<void> => {
      if (released) {
        return;
      }
      released = true;

      // The token is both in the filename and in the record. If the lock
      // path was replaced, or its record was corrupted, do nothing: the
      // current owner must never be affected by an old release callback.
      let metadata: LockMetadata;
      try {
        metadata = parseLockMetadata(await readFile(ownerPath, "utf8"));
      } catch (error: unknown) {
        if (isNotFound(error) || isNotDirectory(error)) {
          return;
        }
        return;
      }
      if (metadata.ownerToken !== ownerToken) {
        return;
      }

      try {
        await unlink(ownerPath);
      } catch (error: unknown) {
        if (isNotFound(error) || isNotDirectory(error)) {
          return;
        }
        throw error;
      }

      // rmdir is intentionally non-recursive. If a replacement owner has
      // appeared, its token file makes this fail without touching it.
      try {
        await rmdir(lockPath);
      } catch (error: unknown) {
        if (!isNotFound(error) && !isNotDirectory(error) && !isDirectoryNotEmpty(error)) {
          throw error;
        }
      }
    },
  };
}

async function inspectLock(path: string): Promise<ExistingLock | undefined> {
  let fileInfo: { isDirectory(): boolean; mtimeMs: number };
  try {
    fileInfo = await stat(path);
  } catch (error: unknown) {
    if (isNotFound(error)) {
      return undefined;
    }
    throw error;
  }

  if (!fileInfo.isDirectory()) {
    const metadata = await readMetadata(path);
    if (metadata === undefined) {
      return undefined;
    }
    return {
      metadata,
      ownerRecords: [],
      isDirectory: false,
      modifiedAtMs: fileInfo.mtimeMs,
    };
  }

  let entries: string[];
  try {
    entries = await readdir(path);
  } catch (error: unknown) {
    if (isNotFound(error) || isNotDirectory(error)) {
      return undefined;
    }
    throw error;
  }
  const ownerEntries = entries.filter((entry) => entry.startsWith(LOCK_OWNER_PREFIX));
  const ownerRecords: LockMetadata[] = [];
  for (const entry of ownerEntries) {
    const metadata = await readMetadata(join(path, entry));
    if (metadata === undefined) {
      return undefined;
    }
    ownerRecords.push(metadata);
  }
  const removableEntry = ownerEntries[0] ?? entries[0];
  return {
    metadata: ownerRecords.length === 1 ? ownerRecords[0]! : {},
    ownerRecords,
    isDirectory: true,
    ...(removableEntry === undefined ? {} : { removablePath: join(path, removableEntry) }),
    modifiedAtMs: fileInfo.mtimeMs,
  };
}

async function readMetadata(path: string): Promise<LockMetadata | undefined> {
  try {
    return parseLockMetadata(await readFile(path, "utf8"));
  } catch (error: unknown) {
    if (isNotFound(error) || isNotDirectory(error)) {
      return undefined;
    }
    throw error;
  }
}

function parseLockMetadata(raw: string): LockMetadata {
  try {
    const value: unknown = JSON.parse(raw);
    if (typeof value !== "object" || value === null) {
      return {};
    }
    const record = value as Record<string, unknown>;
    return {
      ...(typeof record.ownerToken === "string" && record.ownerToken.length > 0
        ? { ownerToken: record.ownerToken }
        : {}),
      ...(isValidPid(record.pid) ? { pid: record.pid } : {}),
      ...(typeof record.createdAt === "string" ? { createdAt: record.createdAt } : {}),
    };
  } catch {
    return {};
  }
}

function reclaimable(lock: ExistingLock, staleAfterMs: number): boolean {
  const records = lock.ownerRecords.length === 0 ? [lock.metadata] : lock.ownerRecords;
  if (records.some((metadata) => metadata.pid !== undefined && isProcessAlive(metadata.pid))) {
    return false;
  }
  if (records.some((metadata) => metadata.pid !== undefined)) {
    return true;
  }
  const createdAtMs = lock.metadata.createdAt === undefined ? undefined : Date.parse(lock.metadata.createdAt);
  const referenceTime = Number.isFinite(createdAtMs) ? createdAtMs : lock.modifiedAtMs;
  if (referenceTime === undefined) {
    return false;
  }
  const ageMs = Math.max(0, Date.now() - referenceTime);
  return ageMs >= staleAfterMs;
}

function runLocked(path: string, lock: ExistingLock, extra: Record<string, unknown> = {}): DomainError {
  return new DomainError("RUN_LOCKED", "artifact", `Run lock is already held: ${path}`, true, {
    path,
    ...(lock.metadata.pid === undefined ? {} : { pid: lock.metadata.pid }),
    ...(lock.metadata.createdAt === undefined ? {} : { createdAt: lock.metadata.createdAt }),
    ...extra,
  });
}

function isValidPid(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error: unknown) {
    return typeof error === "object" && error !== null && "code" in error && error.code === "EPERM";
  }
}

function isAlreadyExists(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "EEXIST";
}

function isNotFound(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function isNotDirectory(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOTDIR";
}

function isDirectoryNotEmpty(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && (error.code === "ENOTEMPTY" || error.code === "EEXIST");
}

function isConcurrentRenameRace(error: unknown): boolean {
  // macOS can report EINVAL when another contender has renamed the exact
  // owner entry between our inspection and rename. The path is private to
  // this lock protocol, so this is a namespace state change to retry rather
  // than a fatal adapter error.
  return typeof error === "object" && error !== null && "code" in error && error.code === "EINVAL";
}

/*
 * The lock protocol relies on mkdir and rename within one parent directory.
 * Both are atomic on the POSIX filesystems used by the validated CI path and
 * are the corresponding atomic namespace operations on Windows. The overall
 * V2 support claim remains POSIX-only until Windows process-tree cleanup and
 * CI are separately accepted.
 */

export function makeTemporaryRoot(prefix = "pure-auto-codeql-v2-"): string {
  return `/tmp/${prefix}${randomUUID()}`;
}
