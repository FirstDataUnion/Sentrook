/**
 * Whether Sentrook's approval cards reach the owner in each chat app OpenClaw has on, read from OpenClaw's config, for
 * the setup report (`setupReport.ApprovalRoute`). OpenClaw shows a plugin's approval card in a chat app only once that
 * app's approval route is set up; until then a review there is refused:
 *
 * - Discord: `channels.discord.execApprovals.enabled` true or "auto" (off when unset), and an approver.
 * - Telegram: on unless `enabled` is false, and an approver.
 * - An approver: `execApprovals.approvers` on the channel or one of its `accounts`, or a `<app>:<id>` entry in
 *   `commands.ownerAllowFrom` (OpenClaw fills it when the owner approves the first pairing).
 * - WhatsApp and Signal: cards are forwarded to the chat the request came from with `approvals.plugin.enabled` true.
 * - Slack: the card shows in the same chat, for the accounts in Slack's `allowFrom`; nothing to set up.
 * - Any other app: Sentrook cannot tell.
 *
 * Every command in the text is for the owner to run in a terminal; the agent never changes OpenClaw's approval
 * settings.
 */

import type { ApprovalRoute } from "./setupReport.ts";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const list = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && !!x.trim()) : []);

/** The channel's own `execApprovals` and each account's. */
function execApprovals(channel: Obj): Obj[] {
  const out: Obj[] = [];
  if (isObj(channel.execApprovals)) out.push(channel.execApprovals);
  if (isObj(channel.accounts)) {
    for (const account of Object.values(channel.accounts)) {
      if (isObj(account) && account.enabled !== false && isObj(account.execApprovals)) out.push(account.execApprovals);
    }
  }
  return out;
}

const NAMES: Record<string, string> = { discord: "Discord", telegram: "Telegram" };

function execRoute(app: string, channel: Obj, owners: string[], defaultOn: boolean): ApprovalRoute {
  const blocks = execApprovals(channel);
  const on = (e: Obj) => e.enabled === true || e.enabled === "auto" || (defaultOn && e.enabled === undefined);
  const enabled = blocks.length ? blocks.some(on) : defaultOn;
  const approver = blocks.some((e) => list(e.approvers).length > 0) || owners.some((o) => o.toLowerCase().startsWith(`${app}:`));
  if (!enabled) {
    return {
      app,
      ok: false,
      text:
        "approval cards are off, so a review there is refused. The owner runs, in a terminal: " +
        `\`openclaw config set channels.${app}.execApprovals.enabled true\``,
    };
  }
  if (!approver) {
    return {
      app,
      ok: false,
      text:
        "no approver, so a review there is refused. The owner runs, in a terminal: " +
        `\`openclaw config set channels.${app}.execApprovals.approvers '["<their ${NAMES[app]} user id>"]'\``,
    };
  }
  return { app, ok: true, text: "cards reach the owner (approval cards on, approver set)." };
}

function forwardRoute(app: string, hostConfig: Obj): ApprovalRoute {
  const approvals = isObj(hostConfig.approvals) ? hostConfig.approvals : {};
  const plugin = isObj(approvals.plugin) ? approvals.plugin : {};
  const extra = app === "signal" ? " Signal also needs the owner in `channels.signal.allowFrom`." : "";
  if (plugin.enabled === true) return { app, ok: true, text: `cards are forwarded to the chat the request came from.${extra}` };
  return {
    app,
    ok: false,
    text:
      "cards are not forwarded, so a review there is refused. The owner runs, in a terminal: " +
      `\`openclaw config set approvals.plugin.enabled true\` and \`openclaw config set approvals.plugin.mode session\`.${extra}`,
  };
}

/** One line per chat app OpenClaw has on (a `channels.<app>` entry not set `enabled: false`), by name; null when
 * OpenClaw's config cannot be read. */
export function approvalRoutes(hostConfig: unknown): ApprovalRoute[] | null {
  if (!isObj(hostConfig)) return null;
  const channels = isObj(hostConfig.channels) ? hostConfig.channels : {};
  const owners = list(isObj(hostConfig.commands) ? hostConfig.commands.ownerAllowFrom : undefined);
  const out: ApprovalRoute[] = [];
  for (const app of Object.keys(channels).sort()) {
    const channel = channels[app];
    if (!isObj(channel) || channel.enabled === false) continue;
    const id = app.toLowerCase();
    if (id === "discord") out.push(execRoute(id, channel, owners, false));
    else if (id === "telegram") out.push(execRoute(id, channel, owners, true));
    else if (id === "whatsapp" || id === "signal") out.push(forwardRoute(id, hostConfig));
    else if (id === "slack") out.push({ app: id, ok: true, text: "cards show in the same chat, for the accounts in Slack's `allowFrom`; nothing to set up." });
    else out.push({ app, ok: null, text: "Sentrook cannot tell whether cards reach the owner there." });
  }
  return out;
}
