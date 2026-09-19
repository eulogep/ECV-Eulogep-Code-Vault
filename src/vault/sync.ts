import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import { EcvError } from "../errors.js";
import { diataCanonicalPath } from "./paths.js";
import type { Vault } from "./vault.js";

const SKIP_NAMES = new Set([".git", "node_modules", ".DS_Store", ".ecv"]);
export const MAX_SYNC_FILE_BYTES = 50 * 1024 * 1024;

export interface SyncOptions {
  /** Vault directory the tree is mapped into, e.g. "app" puts ./a.ts at app/a.ts. */
  prefix?: string;
  /** Delete vault files under the prefix that no longer exist in the directory. */
  prune?: boolean;
  /** Allow pruning when the directory contains no files at all. */
  force?: boolean;
}

export interface SyncResult {
  added: number;
  updated: number;
  unchanged: number;
  removed: number;
  skipped: string[];
}

async function walk(root: string, current = root): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await readdir(current, { withFileTypes: true })) {
    if (SKIP_NAMES.has(entry.name) || entry.isSymbolicLink()) continue;
    const full = join(current, entry.name);
    if (entry.isDirectory()) files.push(...(await walk(root, full)));
    else if (entry.isFile()) files.push(full);
  }
  return files;
}

/** Makes the vault match a working directory, writing only files whose content changed. */
export async function syncDirectory(vault: Vault, root: string, options: SyncOptions = {}): Promise<SyncResult> {
  const prefix = options.prefix ? `${diataCanonicalPath(options.prefix)}/` : "";
  const local = new Map<string, string>();
  const result: SyncResult = { added: 0, updated: 0, unchanged: 0, removed: 0, skipped: [] };

  for (const file of await walk(root)) {
    const target = diataCanonicalPath(`${prefix}${relative(root, file)}`);
    local.set(target, file);
  }
  if (options.prune && local.size === 0 && !options.force) {
    throw new EcvError("EMPTY_SOURCE", "refusing to prune: the directory has no files (use --force if that is intended)");
  }

  const known = new Map((await vault.list()).map((file) => [file.path, file.sha256]));
  for (const [target, file] of local) {
    if ((await stat(file)).size > MAX_SYNC_FILE_BYTES) {
      result.skipped.push(file);
      continue;
    }
    const data = await readFile(file);
    const previous = known.get(target);
    if (previous === createHash("sha256").update(data).digest("hex")) {
      result.unchanged += 1;
      continue;
    }
    await vault.write(target, data);
    if (previous === undefined) result.added += 1;
    else result.updated += 1;
  }

  if (options.prune) {
    for (const path of known.keys()) {
      if (path.startsWith(prefix) && !local.has(path)) {
        await vault.delete(path);
        result.removed += 1;
      }
    }
  }
  return result;
}
