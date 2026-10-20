/**
 * `openclaw sentrook verify`
 */

import { formatVerifyReport, runVerify } from "./verify.ts";

/** The commander-like surface OpenClaw passes to registerCli. */
interface CliCommand {
  description: (text: string) => CliCommand;
  command: (name: string) => CliCommand;
  option: (flags: string, description?: string) => CliCommand;
  action: (fn: (...args: any[]) => void | Promise<void>) => CliCommand;
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
}
