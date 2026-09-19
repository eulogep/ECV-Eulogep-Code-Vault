import { openSync, writeSync } from "node:fs";
import { ReadStream } from "node:tty";
import { AuthError } from "../errors.js";

export interface Prompter {
  /** False when answers come from a fixed source, so retrying cannot help. */
  readonly interactive: boolean;
  /** Reads a secret without echoing it. */
  secret(question: string): Promise<string>;
  /** Asks a yes/no question; anything but an explicit yes is a no. */
  confirm(question: string): Promise<boolean>;
}

/**
 * Prompts go to the controlling terminal (/dev/tty), never through stdin/stdout,
 * so an MCP client speaking over stdio cannot answer them on the human's behalf.
 */
function readFromTerminal(question: string, echo: boolean): Promise<string> {
  return new Promise((resolve, reject) => {
    let fd: number;
    try {
      fd = openSync("/dev/tty", "r+");
    } catch {
      reject(new AuthError("no controlling terminal available for the prompt"));
      return;
    }
    const input = new ReadStream(fd);
    writeSync(fd, question);
    input.setRawMode(true);
    let buffer = "";
    const finish = (error?: Error): void => {
      input.setRawMode(false);
      input.destroy();
      try {
        writeSync(fd, "\n");
      } catch {
        // terminal already closed
      }
      if (error) reject(error);
      else resolve(buffer);
    };
    input.on("data", (chunk: Buffer) => {
      for (const ch of chunk.toString("utf8")) {
        if (ch === "\r" || ch === "\n") return finish();
        if (ch === "\u0003") return finish(new AuthError("cancelled"));
        if (ch === "\u007f" || ch === "\b") {
          buffer = buffer.slice(0, -1);
        } else if (ch >= " ") {
          buffer += ch;
          if (echo) writeSync(fd, ch);
        }
      }
    });
    input.on("error", (error) => finish(error));
  });
}

export function terminalPrompter(): Prompter {
  return {
    interactive: true,
    secret: (question) => readFromTerminal(question, false),
    confirm: async (question) => /^y(es)?$/i.test((await readFromTerminal(`${question} [y/N] `, true)).trim()),
  };
}

/**
 * Non-interactive fallback for CI: ECV_PASSPHRASE is moved out of this
 * process's environment (so children can't inherit it) and kept in memory.
 * Prefer Touch ID or the terminal prompt.
 */
export function defaultPrompter(env: NodeJS.ProcessEnv = process.env): Prompter {
  const terminal = terminalPrompter();
  const fromEnv = env.ECV_PASSPHRASE;
  delete env.ECV_PASSPHRASE;
  return {
    interactive: fromEnv === undefined,
    secret: (question) => (fromEnv !== undefined ? Promise.resolve(fromEnv) : terminal.secret(question)),
    confirm: (question) => terminal.confirm(question),
  };
}
