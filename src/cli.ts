#!/usr/bin/env node
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { defaultPrompter, type Prompter } from "./auth/prompt.js";
import { rosaireUnlock, type AuthContext } from "./auth/rosaire.js";
import { TouchIdBridge } from "./auth/touchid.js";
import { EcvError } from "./errors.js";
import { nasaBootstrap } from "./gateway/bootstrap.js";
import { PLATEAU_PRESETS, presetPolicy, rosaireValidatePolicy } from "./policy/plateau.js";
import { VERSION } from "./version.js";
import { syncDirectory } from "./vault/sync.js";
import { Vault } from "./vault/vault.js";

const MIN_PASSPHRASE_LENGTH = 12;

const HELP = `ecv ${VERSION} — Eulogep Code Vault

Usage: ecv <command> [options]

Vault
  init [--touchid]            Create a vault (passphrase + recovery code)
  import <dir> [--prefix p]   Encrypt a directory tree into the vault (changed files only)
  seal <dir> [--prune]        Sync a working copy back; --prune also deletes files removed from it
  ls                          List files
  cat <path>                  Print a file
  put <path>                  Store stdin as a file
  rm <path>                   Delete a file
  checkout <dest> [--force]   Decrypt the whole vault into a directory (plaintext on disk!)
  status                      Show vault id and unlock methods (no unlock needed)

Access control
  policy show                 Print the agent policy
  policy set <preset|file>    Apply a preset (${Object.keys(PLATEAU_PRESETS).join(", ")}) or a JSON policy file
  gateway [--ttl seconds]     Serve the vault to AI agents over MCP (stdio)
  audit [--verify]            Show the tamper-evident audit log
  touchid enroll|remove       Manage the Touch ID unlock method (macOS)
  passwd                      Change the passphrase
  recovery rotate             Issue a new recovery code (the old one stops working)

Global options
  -v, --vault <dir>           Vault directory (default: $ECV_VAULT or ./.ecv)
      --recovery              Unlock with the recovery code
      --passphrase-only       Skip Touch ID
  -h, --help                  Show help
`;

const stderr = (message: string): void => void process.stderr.write(`${message}\n`);
const stdout = (message: string): void => void process.stdout.write(`${message}\n`);

function context(prompter: Prompter, reason: string): AuthContext {
  return { prompter, touchId: TouchIdBridge.locate(), reason, log: stderr };
}

async function readStdin(): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

async function main(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      vault: { type: "string", short: "v" },
      recovery: { type: "boolean" },
      "passphrase-only": { type: "boolean" },
      touchid: { type: "boolean" },
      prefix: { type: "string" },
      force: { type: "boolean" },
      prune: { type: "boolean" },
      verify: { type: "boolean" },
      ttl: { type: "string" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean" },
    },
  });
  const [command, ...rest] = positionals;
  if (values.version) return stdout(VERSION);
  if (values.help || !command || command === "help") return stdout(HELP);

  const vaultDir = resolve(values.vault ?? process.env.ECV_VAULT ?? ".ecv");
  const prompter = defaultPrompter();
  const unlock = (reason: string): Promise<Vault> =>
    rosaireUnlock(vaultDir, context(prompter, reason), {
      recovery: values.recovery,
      passphraseOnly: values["passphrase-only"],
    });

  switch (command) {
    case "init": {
      const passphrase = await prompter.secret("New passphrase: ");
      if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
        throw new EcvError("WEAK", `passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
      }
      if (passphrase !== (await prompter.secret("Repeat passphrase: "))) throw new EcvError("MISMATCH", "passphrases do not match");
      const { vault, recoveryCode } = await Vault.create(vaultDir, { passphrase });
      try {
        stdout(`Vault created in ${vaultDir}\n`);
        stdout("RECOVERY CODE — write it down and keep it offline. It is shown only once:");
        stdout(`\n    ${recoveryCode}\n`);
        if (values.touchid) {
          const bridge = TouchIdBridge.locate();
          if (!bridge) throw new EcvError("NO_HELPER", "Touch ID helper not found; run 'npm run build:native' on macOS");
          await vault.addDeviceSlot("default", await bridge.enroll("default", "Enrol Touch ID for this vault"));
          stdout("Touch ID enrolled.");
        }
      } finally {
        vault.close();
      }
      return;
    }

    case "status": {
      const header = await Vault.readHeader(vaultDir);
      stdout(`vault:   ${vaultDir}\nid:      ${header.id}\ncreated: ${header.createdAt}\nstate:   locked`);
      stdout(`unlock:  ${header.slots.map((slot) => slot.type).join(", ")}`);
      return;
    }

    case "import":
    case "seal": {
      const source = rest[0];
      if (!source) throw new EcvError("USAGE", `usage: ecv ${command} <dir> [--prefix p]${command === "seal" ? " [--prune]" : ""}`);
      const vault = await unlock(command === "seal" ? "Seal a working copy into the vault" : "Import files into the vault");
      try {
        const result = await syncDirectory(vault, resolve(source), {
          prefix: values.prefix,
          prune: command === "seal" && values.prune,
          force: values.force,
        });
        for (const file of result.skipped) stderr(`skipped (too large): ${file}`);
        const summary = `${result.added} added, ${result.updated} updated, ${result.unchanged} unchanged, ${result.removed} removed`;
        await vault.audit({ actor: "cli", action: command, decision: "allow", detail: summary });
        stdout(summary);
      } finally {
        vault.close();
      }
      return;
    }

    case "ls":
    case "cat":
    case "put":
    case "rm":
    case "checkout": {
      const vault = await unlock(`ecv ${command}`);
      try {
        if (command === "ls") {
          for (const file of await vault.list()) stdout(`${String(file.size).padStart(10)}  ${file.path}`);
        } else if (command === "cat") {
          process.stdout.write(await vault.read(rest[0] ?? ""));
          await vault.audit({ actor: "cli", action: "read", path: rest[0], decision: "allow" });
        } else if (command === "put") {
          if (!rest[0]) throw new EcvError("USAGE", "usage: ecv put <path> < file");
          await vault.write(rest[0], await readStdin());
          await vault.audit({ actor: "cli", action: "write", path: rest[0], decision: "allow" });
        } else if (command === "rm") {
          await vault.delete(rest[0] ?? "");
          await vault.audit({ actor: "cli", action: "delete", path: rest[0], decision: "allow" });
        } else {
          if (!rest[0]) throw new EcvError("USAGE", "usage: ecv checkout <dest> [--force]");
          const dest = resolve(rest[0]);
          const existing = await readdir(dest).catch(() => []);
          if (existing.length > 0 && !values.force) {
            throw new EcvError("NOT_EMPTY", `${dest} is not empty; use --force to write into it`);
          }
          const files = await vault.list();
          for (const file of files) {
            const target = join(dest, file.path);
            await mkdir(dirname(target), { recursive: true, mode: 0o700 });
            await writeFile(target, await vault.read(file.path), { mode: 0o600 });
          }
          await vault.audit({ actor: "cli", action: "checkout", decision: "allow", detail: `${files.length} files` });
          stderr(`Wrote ${files.length} files to ${dest}. This copy is NOT encrypted.`);
        }
      } finally {
        vault.close();
      }
      return;
    }

    case "policy": {
      const [sub, arg] = rest;
      const vault = await unlock(`ecv policy ${sub ?? ""}`.trim());
      try {
        if (sub === "show") {
          stdout(JSON.stringify(await vault.getPolicy(), null, 2));
        } else if (sub === "set" && arg) {
          const policy = arg in PLATEAU_PRESETS ? presetPolicy(arg) : rosaireValidatePolicy(JSON.parse(await readFile(arg, "utf8")));
          await vault.setPolicy(policy);
          await vault.audit({ actor: "cli", action: "policy-set", decision: "allow", detail: policy.preset ?? "custom" });
          stdout(`Policy set: ${policy.preset ?? "custom"}`);
        } else {
          throw new EcvError("USAGE", "usage: ecv policy show | ecv policy set <preset|file.json>");
        }
      } finally {
        vault.close();
      }
      return;
    }

    case "audit": {
      const vault = await unlock("Read the audit log");
      try {
        const report = await vault.verifyAudit();
        if (!values.verify) {
          for (const entry of report.entries) {
            stdout(`${entry.ts}  ${entry.actor.padEnd(14)} ${entry.action.padEnd(9)} ${entry.decision.padEnd(18)} ${entry.path ?? ""} ${entry.detail ?? ""}`.trimEnd());
          }
        }
        if (!report.ok) throw new EcvError("AUDIT", `audit log is NOT intact: ${report.error}`);
        stdout(`audit log intact (${report.entries.length} records)`);
      } finally {
        vault.close();
      }
      return;
    }

    case "touchid": {
      const bridge = TouchIdBridge.locate();
      if (!bridge) throw new EcvError("NO_HELPER", "Touch ID helper not found; run 'npm run build:native' on macOS");
      const vault = await unlock("Change Touch ID settings");
      try {
        if (rest[0] === "enroll") {
          await vault.addDeviceSlot("default", await bridge.enroll("default", "Enrol Touch ID for this vault"));
          stdout("Touch ID enrolled.");
        } else if (rest[0] === "remove") {
          await vault.removeDeviceSlot("default");
          await bridge.remove("default");
          stdout("Touch ID removed.");
        } else {
          throw new EcvError("USAGE", "usage: ecv touchid enroll|remove");
        }
      } finally {
        vault.close();
      }
      return;
    }

    case "passwd": {
      const vault = await unlock("Change the vault passphrase");
      try {
        const passphrase = await prompter.secret("New passphrase: ");
        if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
          throw new EcvError("WEAK", `passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
        }
        if (passphrase !== (await prompter.secret("Repeat passphrase: "))) throw new EcvError("MISMATCH", "passphrases do not match");
        await vault.changePassphrase(passphrase);
        await vault.audit({ actor: "cli", action: "passwd", decision: "allow" });
        stdout("Passphrase changed. Note: the data key is unchanged; copies of the vault made earlier still open with the old passphrase.");
      } finally {
        vault.close();
      }
      return;
    }

    case "recovery": {
      if (rest[0] !== "rotate") throw new EcvError("USAGE", "usage: ecv recovery rotate");
      const vault = await unlock("Rotate the recovery code");
      try {
        const code = await vault.rotateRecoveryCode();
        await vault.audit({ actor: "cli", action: "recovery-rotate", decision: "allow" });
        stdout("NEW RECOVERY CODE — the previous one no longer works. Shown only once:");
        stdout(`\n    ${code}\n`);
      } finally {
        vault.close();
      }
      return;
    }

    case "gateway": {
      const ttl = values.ttl === undefined ? undefined : Number.parseInt(values.ttl, 10);
      if (ttl !== undefined && (!Number.isInteger(ttl) || ttl < 30)) throw new EcvError("USAGE", "--ttl must be at least 30 seconds");
      stderr(`ecv gateway ${VERSION} serving ${vaultDir} on stdio`);
      await nasaBootstrap({
        vaultDir,
        auth: context(prompter, "An AI agent is requesting access to your vault"),
        ttlSeconds: ttl,
      });
      return;
    }

    default:
      throw new EcvError("USAGE", `unknown command '${command}'\n\n${HELP}`);
  }
}

main(process.argv.slice(2)).catch((error: unknown) => {
  stderr(`ecv: ${error instanceof EcvError ? error.message : ((error as Error).stack ?? String(error))}`);
  process.exit(1);
});
