/**
 * `openclaw sentrook login` (sign in in a browser and store the scan credentials), `verify`, `status`, `history [n]`, `why [request_id]`, `grants`, `grant`, `revoke`
 * and `bind`.
 *
 * The owner-only ones print what their `/sentrook-<verb>` chat commands return. On the command line
 * the person typing is at the gateway host's shell, so counts as the owner; each run is audited as a
 * `command` record with basis `local_terminal`.
 */

import { envWithOpenclawDotenv } from "./auth.ts";
import { OWNER_SUBCOMMANDS, runSentrookCommand, SUBCOMMANDS } from "./commands.ts";
import { resolveConfig } from "./config.ts";
import { auditCommand } from "./owner.ts";
import { TrafficLog } from "./traffic.ts";
import { formatVerifyReport, runVerify } from "./verify.ts";
import { Cancelled, defaultLoginDeps, type LoginDeps, runLogin } from "./login.ts";

/** The commander-like surface OpenClaw passes to registerCli. */
interface CliCommand {
  description: (text: string) => CliCommand;
  command: (name: string) => CliCommand;
  option: (flags: string, description?: string) => CliCommand;
  action: (fn: (...args: any[]) => void | Promise<void>) => CliCommand;
  /** commander: unknown options become arguments, so the grant flags reach the shared parser. */
  allowUnknownOption?: () => CliCommand;
}

/** `hostConfig` reads OpenClaw's own config for verify. */
export function registerSentrookCli(
  program: { command: (name: string) => CliCommand },
  pluginConfig: () => Record<string, unknown>,
  hostConfig: () => unknown = () => undefined,
): void {
  const root = program.command("sentrook").description("Sentrook plugin helpers");
  root
    .command("verify")
    .description("Check endpoints, credentials, scanner health and token mint")
    .action(async () => {
      const checks = await runVerify(pluginConfig(), { hostConfig: hostConfig() });
      console.log(formatVerifyReport(checks));
      if (checks.some((c) => !c.ok)) process.exitCode = 1;
    });
  root
    .command("login")
    .description("Sign in with your FIDU account in a browser and store Sentrook's credentials")
    .option("--name <label>", "How this machine is listed in your account (default: OpenClaw on <hostname>)")
    .action(async (opts?: { name?: string }) => {
      process.exitCode = await loginFromCli(pluginConfig(), hostConfig, opts?.name);
    });
  root
    .command("status")
    .description(SUBCOMMANDS.status!.description)
    .action(async () => {
      console.log(await runSentrookCommand("status", { pluginConfig: pluginConfig(), env: process.env }));
    });
  for (const [verb, sub] of Object.entries(OWNER_SUBCOMMANDS)) {
    const command = root.command(sub.cliRest ? `${verb} [args...]` : `${verb} ${sub.args.replace("|last", "")}`.trimEnd());
    if (sub.cliRest) command.allowUnknownOption?.();
    command.description(sub.description).action(async (arg?: unknown) => {
      const { trafficLog } = resolveConfig(pluginConfig(), envWithOpenclawDotenv(process.env));
      // No sender id on the command line, so no salt is needed.
      const audit = { traffic: new TrafficLog(trafficLog.path, trafficLog.maxBytes, trafficLog.enabled), salt: () => "" };
      auditCommand(audit, {}, verb, "allowed", ["local_terminal"]);
      const ctx = {
        pluginConfig: pluginConfig(),
        env: process.env,
        owner: {
          by: { basis: ["local_terminal"], channel: null, sender_ref: null },
          beforeWrite: () => undefined,
          record: (record: Record<string, unknown>) => audit.traffic.write(record),
        },
      };
      const rest = Array.isArray(arg) ? arg.join(" ") : typeof arg === "string" ? arg.trim() : "";
      console.log(await sub.run(ctx, rest));
    });
  }
}

/**
 * The login with the real network, clock and terminal. Ctrl-C while waiting ends it cleanly with nothing changed.
 * The checks afterwards use the new values directly: the running gateway keeps any earlier ones until it restarts.
 */
export async function loginFromCli(
  pluginConfig: Record<string, unknown>,
  hostConfig: () => unknown,
  name: string | undefined,
  overrides: Partial<LoginDeps> = {},
): Promise<number> {
  const env = envWithOpenclawDotenv(process.env);
  const cancel = new AbortController();
  const onInt = () => cancel.abort();
  // While this runs, Ctrl-C ends the sign-in cleanly (whatever it is waiting for) instead of killing the process.
  process.on("SIGINT", onInt);
  const deps: LoginDeps = {
    ...defaultLoginDeps(process.env),
    cancel: cancel.signal,
    sleep: (s) =>
      new Promise((resolve, reject) => {
        if (cancel.signal.aborted) return reject(new Cancelled());
        const timer = setTimeout(resolve, s * 1000);
        cancel.signal.addEventListener(
          "abort",
          () => {
            clearTimeout(timer);
            reject(new Cancelled());
          },
          { once: true },
        );
      }),
    verify: async (values) => {
      const checks = await runVerify(pluginConfig, { env: { ...process.env, ...values }, hostConfig: hostConfig() });
      return { report: formatVerifyReport(checks), ok: checks.every((c) => c.ok) };
    },
    ...overrides,
  };
  try {
    return await runLogin(pluginConfig, { name, env, processEnv: process.env, deps });
  } finally {
    process.removeListener("SIGINT", onInt);
  }
}
