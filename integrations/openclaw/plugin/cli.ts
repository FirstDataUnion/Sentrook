/**
 * OpenClaw root CLI: `openclaw sentrook configure|verify`
 */

import {
  collectAnswersInteractive,
  collectAnswersNonInteractive,
  createStdioIo,
  runConfigure,
  type ConfigureAnswers,
} from "./configure.ts";
import { formatVerifyReport, runVerify } from "./verify.ts";
import { parseOnScanError } from "./scanErrorPolicy.ts";

/** Minimal commander-like surface OpenClaw passes to registerCli. */
export interface CliProgram {
  command: (name: string) => CliCommand;
}

export interface CliCommand {
  description: (text: string) => CliCommand;
  command: (name: string) => CliCommand;
  option: (flags: string, description?: string) => CliCommand;
  action: (fn: (...args: any[]) => void | Promise<void>) => CliCommand;
}

export interface ConfigureCliOptions {
  nonInteractive?: boolean;
  url?: string;
  timeoutMs?: string;
  /** true|false — contribute sanitized review feedback to community corpus */
  contributeCorpus?: string;
  clientId?: string;
  clientSecret?: string;
  apiKey?: string;
  stateDir?: string;
  onScanError?: string;
}

export interface VerifyCliOptions {
  url?: string;
  stateDir?: string;
  timeoutMs?: string;
}

function parseBool(raw?: string): boolean | undefined {
  if (raw === undefined) return undefined;
  const v = raw.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(v)) return true;
  if (["0", "false", "no", "off"].includes(v)) return false;
  return undefined;
}

function parseTimeout(raw?: string): number | undefined {
  if (!raw) return undefined;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

function seedFromOptions(opts: ConfigureCliOptions): Partial<ConfigureAnswers> {
  return {
    url: opts.url,
    timeoutMs: parseTimeout(opts.timeoutMs),
    contributeCorpus: parseBool(opts.contributeCorpus),
    clientId: opts.clientId || process.env.SENTROOK_SCAN_CLIENT_ID,
    clientSecret: opts.clientSecret || process.env.SENTROOK_SCAN_CLIENT_SECRET,
    apiKey: opts.apiKey || process.env.SENTROOK_SCAN_API_KEY,
    onScanError: opts.onScanError
      ? parseOnScanError(opts.onScanError)
      : undefined,
  };
}

export async function runConfigureCommand(opts: ConfigureCliOptions): Promise<void> {
  const seed = seedFromOptions(opts);
  const nonInteractive = opts.nonInteractive === true || !process.stdin.isTTY;

  let answers: ConfigureAnswers;
  if (nonInteractive) {
    answers = collectAnswersNonInteractive(seed);
  } else {
    const io = await createStdioIo();
    try {
      answers = await collectAnswersInteractive(io, seed);
    } finally {
      io.close();
    }
  }

  await runConfigure(answers, { stateDir: opts.stateDir });
}

export async function runVerifyCommand(opts: VerifyCliOptions): Promise<void> {
  const result = await runVerify({
    url: opts.url,
    stateDir: opts.stateDir,
    timeoutMs: parseTimeout(opts.timeoutMs),
  });
  console.log(formatVerifyReport(result));
  if (!result.ok) process.exitCode = 1;
}

export function registerSentrookCli(program: CliProgram): void {
  const sentrook = program
    .command("sentrook")
    .description("Sentrook hosted scan plugin helpers");

  sentrook
    .command("configure")
    .description(
      "Configure Sentrook plugin for hosted scan (OIDC credentials + openclaw.json). Does not restart the gateway.",
    )
    .option("--non-interactive", "Skip prompts; require flags/env for credentials")
    .option("--url <url>", "Scan service base URL")
    .option("--timeout-ms <ms>", "Scan POST timeout in ms")
    .option(
      "--contribute-corpus <bool>",
      "Contribute sanitized review feedback to the community corpus (true|false; default true / opt-out)",
    )
    .option("--client-id <id>", "FIDU ID OAuth client_id")
    .option("--client-secret <secret>", "FIDU ID OAuth client_secret")
    .option("--api-key <key>", "Shared scan API key (optional)")
    .option(
      "--on-scan-error <mode>",
      "When Sentrook is unreachable or rate-limited: allow | deny | review (default allow)",
    )
    .option("--state-dir <path>", "OpenClaw state dir (default: OPENCLAW_STATE_DIR / ~/.openclaw)")
    .action(async (opts: ConfigureCliOptions) => {
      try {
        await runConfigureCommand(opts);
      } catch (err) {
        console.error(`sentrook configure failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    });

  sentrook
    .command("verify")
    .description(
      "Check plugin config, scan credentials, and hosted /health (no Python sentrook CLI required).",
    )
    .option("--url <url>", "Scan service base URL (default: from config or hosted default)")
    .option("--state-dir <path>", "OpenClaw state dir (default: OPENCLAW_STATE_DIR / ~/.openclaw)")
    .option("--timeout-ms <ms>", "Health request timeout (default 8000)")
    .action(async (opts: VerifyCliOptions) => {
      try {
        await runVerifyCommand(opts);
      } catch (err) {
        console.error(`sentrook verify failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
      }
    });
}
