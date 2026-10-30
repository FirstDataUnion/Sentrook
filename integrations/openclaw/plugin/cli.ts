/**
 * `openclaw sentrook verify`, `status`, `history [n]`, `why [request_id]`, `grants`, `grant`, `revoke`
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

/** The commander-like surface OpenClaw passes to registerCli. */
interface CliCommand {
  description: (text: string) => CliCommand;
  command: (name: string) => CliCommand;
  option: (flags: string, description?: string) => CliCommand;
  action: (fn: (...args: any[]) => void | Promise<void>) => CliCommand;
  /** commander: unknown options become arguments, so the grant flags reach the shared parser. */
  allowUnknownOption?: () => CliCommand;
}

export function registerSentrookCli(program: { command: (name: string) => CliCommand }, pluginConfig: () => Record<string, unknown>): void {
  const root = program.command("sentrook").description("Sentrook plugin helpers");
  root
    .command("verify")
    .description("Check endpoints, credentials, scanner health and token mint")
    .action(async () => {
      const checks = await runVerify(pluginConfig());
      console.log(formatVerifyReport(checks));
      if (checks.some((c) => !c.ok)) process.exitCode = 1;
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
