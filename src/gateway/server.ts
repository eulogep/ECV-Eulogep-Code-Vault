import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import { EcvError, PolicyError } from "../errors.js";
import { evaluatePolicy, globMatch, type Capability } from "../policy/plateau.js";
import { VERSION } from "../version.js";
import { diataCanonicalPath } from "../vault/paths.js";
import type { Vault } from "../vault/vault.js";
import type { NasaSession } from "./session.js";

const SUPPORTED_PROTOCOLS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_READ_BYTES = 2 * 1024 * 1024;
const MAX_WRITE_BYTES = 5 * 1024 * 1024;
const MAX_LIST_RESULTS = 1000;
const MAX_SEARCH_FILES = 2000;
const MAX_SEARCH_FILE_BYTES = 1024 * 1024;
const MAX_SEARCH_MATCHES = 100;
const MAX_QUERY_LENGTH = 200;

type JsonRpcId = string | number | null;
interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result?: unknown;
  error?: { code: number; message: string };
}

interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

export interface GatewayDeps {
  session: NasaSession;
  /** Human approval for step-up operations. Must fail closed. */
  approve: (reason: string) => Promise<boolean>;
}

interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

const TOOLS: ToolDefinition[] = [
  {
    name: "vault_status",
    description: "Show the remaining session time and the permissions granted to this agent.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "vault_list",
    description: "List files you are allowed to see, optionally under a directory prefix.",
    inputSchema: {
      type: "object",
      properties: { prefix: { type: "string", description: "Directory prefix, e.g. 'src/auth'" } },
      additionalProperties: false,
    },
  },
  {
    name: "vault_read",
    description: "Read a UTF-8 text file from the vault.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "vault_search",
    description: "Case-insensitive literal search across the files you may search.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string" },
        path_glob: { type: "string", description: "Optional glob to restrict the search, e.g. 'src/**/*.ts'" },
      },
      required: ["query"],
      additionalProperties: false,
    },
  },
  {
    name: "vault_write",
    description: "Create or overwrite a UTF-8 text file in the vault.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, content: { type: "string" } },
      required: ["path", "content"],
      additionalProperties: false,
    },
  },
  {
    name: "vault_delete",
    description: "Delete a file. Usually requires explicit human approval.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
      additionalProperties: false,
    },
  },
];

function fail(id: JsonRpcId, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

const text = (value: string): ToolResult => ({ content: [{ type: "text", text: value }] });

/** Argument guards for tool calls (untrusted input from the model). */
function rosaireArgs(args: unknown): Record<string, unknown> {
  if (args === undefined) return {};
  if (typeof args !== "object" || args === null || Array.isArray(args)) {
    throw new EcvError("BAD_ARGS", "tool arguments must be an object");
  }
  return args as Record<string, unknown>;
}

function stringArg(args: Record<string, unknown>, name: string, maxLength = 100_000_000): string {
  const value = args[name];
  if (typeof value !== "string") throw new EcvError("BAD_ARGS", `'${name}' must be a string`);
  if (value.length > maxLength) throw new EcvError("BAD_ARGS", `'${name}' is too long`);
  return value;
}

export class Gateway {
  private clientName = "unknown-client";

  constructor(private readonly deps: GatewayDeps) {}

  async handle(message: unknown): Promise<JsonRpcResponse | undefined> {
    if (typeof message !== "object" || message === null || Array.isArray(message)) {
      return fail(null, -32600, "Invalid Request");
    }
    const request = message as { id?: JsonRpcId; method?: unknown; params?: unknown };
    const isNotification = !("id" in request);
    const id = request.id ?? null;
    if (typeof request.method !== "string") {
      return isNotification ? undefined : fail(id, -32600, "Invalid Request");
    }

    switch (request.method) {
      case "initialize": {
        const params = (request.params ?? {}) as { protocolVersion?: string; clientInfo?: { name?: string } };
        if (typeof params.clientInfo?.name === "string") this.clientName = params.clientInfo.name.slice(0, 64);
        const version =
          params.protocolVersion && SUPPORTED_PROTOCOLS.includes(params.protocolVersion)
            ? params.protocolVersion
            : (SUPPORTED_PROTOCOLS[0] as string);
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: version,
            capabilities: { tools: {} },
            serverInfo: { name: "ecv-gateway", version: VERSION },
          },
        };
      }
      case "ping":
        return { jsonrpc: "2.0", id, result: {} };
      case "tools/list":
        return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
      case "tools/call": {
        const params = (request.params ?? {}) as { name?: unknown; arguments?: unknown };
        if (typeof params.name !== "string" || !TOOLS.some((tool) => tool.name === params.name)) {
          return fail(id, -32602, "Unknown tool");
        }
        return { jsonrpc: "2.0", id, result: await this.callTool(params.name, params.arguments) };
      }
      default:
        return isNotification ? undefined : fail(id, -32601, `Method not found: ${request.method}`);
    }
  }

  private async callTool(name: string, rawArgs: unknown): Promise<ToolResult> {
    let vault: Vault;
    try {
      vault = await this.deps.session.acquire();
    } catch (error) {
      return { ...text(`Vault is locked and could not be unlocked: ${(error as Error).message}`), isError: true };
    }
    try {
      const args = rosaireArgs(rawArgs);
      switch (name) {
        case "vault_status":
          return await this.status(vault);
        case "vault_list":
          return await this.list(vault, args);
        case "vault_read":
          return await this.read(vault, args);
        case "vault_search":
          return await this.search(vault, args);
        case "vault_write":
          return await this.write(vault, args);
        case "vault_delete":
          return await this.remove(vault, args);
        default:
          return { ...text("Unknown tool"), isError: true };
      }
    } catch (error) {
      const message = error instanceof EcvError ? error.message : "internal error";
      if (!(error instanceof EcvError)) process.stderr.write(`ecv-gateway: ${(error as Error).stack ?? error}\n`);
      return { ...text(message), isError: true };
    }
  }

  private async authorize(vault: Vault, capability: Capability, path: string): Promise<void> {
    const decision = evaluatePolicy(await vault.getPolicy(), capability, path);
    const base = { actor: this.clientName, action: capability, path };
    if (decision.effect === "allow") {
      await vault.audit({ ...base, decision: "allow" });
      return;
    }
    if (decision.effect === "step-up") {
      const approved = await this.deps.approve(`${this.clientName} requests '${capability}' on '${path}'`);
      await vault.audit({ ...base, decision: approved ? "step-up-approved" : "step-up-denied" });
      if (!approved) throw new PolicyError("this operation requires human approval, which was not granted");
      return;
    }
    await vault.audit({ ...base, decision: "deny", detail: decision.reason });
    throw new PolicyError(decision.reason);
  }

  private async status(vault: Vault): Promise<ToolResult> {
    const policy = await vault.getPolicy();
    return text(
      JSON.stringify(
        { sessionSecondsRemaining: this.deps.session.remainingSeconds, preset: policy.preset ?? "custom", rules: policy.rules },
        null,
        2,
      ),
    );
  }

  private async list(vault: Vault, args: Record<string, unknown>): Promise<ToolResult> {
    const prefix = args.prefix === undefined || args.prefix === "" ? "" : `${diataCanonicalPath(stringArg(args, "prefix", 1024))}/`;
    const policy = await vault.getPolicy();
    const visible = (await vault.list()).filter(
      (file) => file.path.startsWith(prefix) && evaluatePolicy(policy, "list", file.path).effect === "allow",
    );
    await vault.audit({ actor: this.clientName, action: "list", path: prefix || undefined, decision: "allow", detail: `${visible.length} files` });
    const shown = visible.slice(0, MAX_LIST_RESULTS);
    const lines = shown.map((file) => `${file.path}\t${file.size}`);
    if (visible.length > shown.length) lines.push(`… ${visible.length - shown.length} more (narrow with 'prefix')`);
    return text(lines.length > 0 ? lines.join("\n") : "(no files visible)");
  }

  private async read(vault: Vault, args: Record<string, unknown>): Promise<ToolResult> {
    const path = diataCanonicalPath(stringArg(args, "path", 1024));
    await this.authorize(vault, "read", path);
    const data = await vault.read(path);
    if (data.length > MAX_READ_BYTES) {
      throw new EcvError("TOO_LARGE", `${path} is ${data.length} bytes; the limit is ${MAX_READ_BYTES}`);
    }
    try {
      return text(new TextDecoder("utf-8", { fatal: true }).decode(data));
    } catch {
      throw new EcvError("BINARY", `${path} is not valid UTF-8 text`);
    }
  }

  private async search(vault: Vault, args: Record<string, unknown>): Promise<ToolResult> {
    const query = stringArg(args, "query", MAX_QUERY_LENGTH);
    if (query.length === 0) throw new EcvError("BAD_ARGS", "'query' must not be empty");
    const glob = args.path_glob === undefined ? null : stringArg(args, "path_glob", 512);
    const needle = query.toLowerCase();
    const policy = await vault.getPolicy();
    const candidates = (await vault.list())
      .filter((file) => file.size <= MAX_SEARCH_FILE_BYTES && (glob === null || globMatch(glob, file.path)))
      .filter((file) => evaluatePolicy(policy, "search", file.path).effect === "allow")
      .slice(0, MAX_SEARCH_FILES);

    const matches: string[] = [];
    for (const file of candidates) {
      if (matches.length >= MAX_SEARCH_MATCHES) break;
      const lines = (await vault.read(file.path)).toString("utf8").split("\n");
      for (const [index, line] of lines.entries()) {
        if (line.toLowerCase().includes(needle)) {
          matches.push(`${file.path}:${index + 1}: ${line.trim().slice(0, 200)}`);
          if (matches.length >= MAX_SEARCH_MATCHES) break;
        }
      }
    }
    await vault.audit({ actor: this.clientName, action: "search", decision: "allow", detail: `"${query}" → ${matches.length} matches in ${candidates.length} files` });
    return text(matches.length > 0 ? matches.join("\n") : "(no matches)");
  }

  private async write(vault: Vault, args: Record<string, unknown>): Promise<ToolResult> {
    const path = diataCanonicalPath(stringArg(args, "path", 1024));
    const content = Buffer.from(stringArg(args, "content"), "utf8");
    if (content.length > MAX_WRITE_BYTES) throw new EcvError("TOO_LARGE", `content exceeds ${MAX_WRITE_BYTES} bytes`);
    await this.authorize(vault, "write", path);
    await vault.write(path, content);
    return text(`wrote ${content.length} bytes to ${path}`);
  }

  private async remove(vault: Vault, args: Record<string, unknown>): Promise<ToolResult> {
    const path = diataCanonicalPath(stringArg(args, "path", 1024));
    await this.authorize(vault, "delete", path);
    await vault.delete(path);
    return text(`deleted ${path}`);
  }
}

/** Serves newline-delimited JSON-RPC over the given streams, one message at a time. */
export function serveStdio(gateway: Gateway, input: Readable, output: Writable): Promise<void> {
  const lines = createInterface({ input, crlfDelay: Infinity });
  let chain: Promise<void> = Promise.resolve();
  const send = (response: JsonRpcResponse): void => {
    output.write(`${JSON.stringify(response)}\n`);
  };
  lines.on("line", (line) => {
    if (line.trim().length === 0) return;
    chain = chain.then(async () => {
      let message: unknown;
      try {
        message = JSON.parse(line);
      } catch {
        send(fail(null, -32700, "Parse error"));
        return;
      }
      const response = await gateway.handle(message);
      if (response) send(response);
    });
  });
  return new Promise((resolve) => {
    lines.on("close", () => void chain.then(resolve));
  });
}
