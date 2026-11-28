/**
 * Who the owner trusts besides themselves: trusted users and trusted chats.
 *
 * A trusted user (`/sentrook-trust-user add <platform>:<user id>`, or `trustedSenders` in the config) is a person the
 * owner knows. Their messages are sent as `relation: trusted` (basis `plugin_allowlist:sender`, plus `group_chat` in a
 * group), not as someone else's (`other`). A trusted chat (`/sentrook-trust-chat add <platform>:<chat id>`, or
 * `trustedChats`) is a group or server channel where the owner knows everyone who can post: every member's message
 * there is `trusted` (basis `plugin_allowlist:chat` and `group_chat`). A thread or topic in a trusted chat is covered
 * too: OpenClaw's session key for it starts with its chat's. The owner's own messages stay the owner's.
 *
 * Trusted is never the owner. Grants, bindings, settings, the setup screen and every owner command stay the owner's
 * alone, from a direct message, the Control UI or the command line; the scanner's floors apply whoever sent the turn;
 * a trusted turn is not one the owner attends (no snooze, no grant set by approving a review).
 *
 * **Reviews in a trusted chat.** OpenClaw decides who may answer an approval card in a chat (the approvers in
 * `channels.<channel>.execApprovals.approvers`, else `commands.ownerAllowFrom`), so by default reviews in a trusted
 * chat are answered as anywhere else. A chat added with `--owner-only` holds its reviews on anyone's turn but the
 * owner's instead: the agent says it is waiting, the owner gets a notice where `/sentrook-notify here` sends them and
 * answers it with `/sentrook-allow <id>`, which lets that exact call through once.
 *
 * Both lists are owner-only, changed only where the other owner commands run (never in a group or channel room), and
 * every change is written to the traffic log as a `settings` record that names the platform, never an id. The chat
 * the command was sent from, when it is the owner's direct chat, cannot be trusted as a chat: a person is a trusted
 * user. A trust file that cannot be read trusts nothing beyond the config.
 */

import path from "node:path";

import type { PluginConfig } from "./config.ts";
import { LockTimeoutError, Store, withFileLock } from "./store.ts";

type Entry = Record<string, any>;
export type Cmd = (sub: string) => string;

const PLATFORM = /^[a-z0-9_-]{1,40}$/;
/** A chat or user id as OpenClaw names it: no spaces or control characters (a Matrix room id has colons). */
const ID = /^[^\s\x00-\x1f\x7f]{1,200}$/;
/**
 * The chat platforms a person writes from, by the channel names OpenClaw uses (and the Hermes plugin's, so both read
 * the same `<platform>:<id>`): the only ones a trusted user or chat can be on. OpenClaw's own surfaces (the operator's)
 * and the runs it starts itself are not among them.
 */
export const PLATFORMS: ReadonlySet<string> = new Set([
  "bluebubbles",
  "bot_room",
  "buzz",
  "dingtalk",
  "discord",
  "email",
  "feishu",
  "google_chat",
  "googlechat",
  "imessage",
  "irc",
  "lark",
  "line",
  "matrix",
  "mattermost",
  "msteams",
  "nextcloud-talk",
  "nostr",
  "ntfy",
  "photon",
  "qqbot",
  "signal",
  "simplex",
  "slack",
  "sms",
  "synology-chat",
  "teams",
  "telegram",
  "tlon",
  "twitch",
  "web",
  "wecom",
  "weixin",
  "whatsapp",
  "whatsapp_cloud",
  "yuanbao",
  "zalo",
  "zalouser",
]);
/** Entries kept per list. */
export const MAX_ENTRIES = 200;
export const OWNER_ONLY = "--owner-only";
const FILE = "trust.json";

/** A trusted chat as the config or the trust file names it: `platform:chat id`, and whether its reviews are held. */
export interface TrustedChat {
  chat: string;
  ownerOnly: boolean;
}

/** The trusted users and chats in force. Keys are compared without case (OpenClaw's session keys are lower case). */
export interface Trust {
  /** `platform:user id`, lower case. */
  senders: Set<string>;
  /** Config sender ids without a platform, matched as written (as before platforms were named). */
  bare: Set<string>;
  /** `platform:chat id`, lower case -> owner-only. */
  chats: Map<string, boolean>;
}

/** `<platform>:<id>` as [platform, id], or null. The platform must be a chat platform. */
export function parseRef(raw: unknown): [string, string] | null {
  if (typeof raw !== "string") return null;
  const text = raw.trim();
  const at = text.indexOf(":");
  if (at < 0) return null;
  const platform = text.slice(0, at).toLowerCase();
  const id = text.slice(at + 1);
  if (!PLATFORM.test(platform) || !PLATFORMS.has(platform) || !ID.test(id)) return null;
  return [platform, id];
}

const keyOf = (ref: [string, string]) => `${ref[0]}:${ref[1]}`;

/**
 * `trustedChats` from the config: a list (or comma-separated text) of `platform:chat id`, or of
 * `{ chat, owner_only }`. A chat named twice is owner-only when either says so. Unreadable entries are skipped
 * (`configProblems` names them).
 */
export function parseConfigChats(raw: unknown): TrustedChat[] {
  const items: unknown[] = Array.isArray(raw) ? raw : typeof raw === "string" ? [raw] : [];
  const out = new Map<string, boolean>();
  for (let item of items) {
    let ownerOnly = false;
    if (item && typeof item === "object" && !Array.isArray(item)) {
      ownerOnly = (item as Entry).owner_only === true;
      item = (item as Entry).chat;
    }
    if (typeof item !== "string") continue;
    for (const part of item.split(",")) {
      const ref = parseRef(part);
      if (ref) out.set(keyOf(ref), (out.get(keyOf(ref)) ?? false) || ownerOnly);
    }
  }
  return [...out].map(([chat, ownerOnly]) => ({ chat, ownerOnly }));
}

/** Why a `trustedChats` entry cannot be read, or null when it can. */
export function chatProblem(item: unknown): string | null {
  if (item && typeof item === "object" && !Array.isArray(item)) {
    const rec = item as Entry;
    const unknown = Object.keys(rec).filter((k) => k !== "chat" && k !== "owner_only");
    if (unknown.length) return `has ${unknown.length === 1 ? "a field" : "fields"} other than chat and owner_only; ignored`;
    if (rec.owner_only !== undefined && typeof rec.owner_only !== "boolean") return "owner_only is not true or false; ignored";
    item = rec.chat;
  }
  if (typeof item !== "string") return "not <platform>:<chat id> text or { chat, owner_only }; ignored";
  return item.split(",").every((p) => !p.trim() || parseRef(p)) ? null : "not <platform>:<chat id> on a chat platform; ignored";
}

/** The trusted users and chats from the config alone. */
export function fromConfig(cfg: Partial<Pick<PluginConfig, "trustedSenders" | "trustedChats">>): Trust {
  const senders = new Set<string>();
  const bare = new Set<string>();
  for (const s of cfg.trustedSenders ?? []) {
    const ref = parseRef(s);
    if (ref) senders.add(keyOf(ref).toLowerCase());
    // a bare id, or one with a colon of its own, keeps matching as written
    bare.add(s);
  }
  const chats = new Map<string, boolean>();
  for (const c of cfg.trustedChats ?? []) {
    const k = c.chat.toLowerCase();
    chats.set(k, (chats.get(k) ?? false) || c.ownerOnly);
  }
  return { senders, bare, chats };
}

/** The trust file, empty when absent; null when it cannot be read. */
function load(stateDir: string): Entry | null {
  try {
    return new Store(stateDir).loadTrust();
  } catch {
    return null;
  }
}

function stored(data: Entry | null): { chats: Map<string, boolean>; senders: Set<string> } {
  const chats = new Map<string, boolean>();
  for (const e of Array.isArray(data?.trusted_chats) ? data!.trusted_chats : []) {
    const ref = e && typeof e === "object" ? parseRef(e.chat) : null;
    if (ref) chats.set(keyOf(ref).toLowerCase(), e.owner_only === true);
  }
  const senders = new Set<string>();
  for (const e of Array.isArray(data?.trusted_senders) ? data!.trusted_senders : []) {
    const ref = e && typeof e === "object" ? parseRef(e.user) : null;
    if (ref) senders.add(keyOf(ref).toLowerCase());
  }
  return { chats, senders };
}

/** The config's lists and those the owner set by command. A chat in both is owner-only when either says so. */
export function of(cfg: Pick<PluginConfig, "trustedSenders" | "trustedChats" | "stateDir">): Trust {
  const t = fromConfig(cfg);
  const s = stored(load(cfg.stateDir));
  for (const k of s.senders) t.senders.add(k);
  for (const [k, v] of s.chats) t.chats.set(k, (t.chats.get(k) ?? false) || v);
  return t;
}

/** Whether `senderId` on `platform` is a trusted user: by `platform:id`, or as a bare config id. */
export function isTrustedSender(t: Trust, platform: string | null, senderId: unknown): boolean {
  if (senderId === undefined || senderId === null || senderId === "") return false;
  const id = String(senderId);
  if (t.bare.has(id)) return true;
  if (!platform) return false;
  const p = platform.toLowerCase();
  const ids = id.toLowerCase().startsWith("user:") ? [id, id.slice(5)] : [id];
  return ids.some((i) => t.senders.has(`${p}:${i}`.toLowerCase()));
}

/** The trusted chat `platform:chatId` names: [key, owner-only], or null. */
export function trustedChat(t: Trust, platform: string | null, chatId: string | null): [string, boolean] | null {
  if (!platform || !chatId) return null;
  const key = `${platform}:${chatId}`.toLowerCase();
  return t.chats.has(key) ? [key, t.chats.get(key)!] : null;
}

// ---- the explanations ---------------------------------------------------------------------------------

export const TRUSTED_IS =
  "Trusted is not the owner: their messages count as from someone you know, not a stranger, but grants, settings " +
  "and Sentrook commands stay yours alone, from your direct message, the Control UI or the command line, and " +
  "Sentrook still stops anything risky.";

/** How many trusted users are in force: by `platform:id`, and bare config ids. */
export function userCount(t: Trust): number {
  return t.senders.size + [...t.bare].filter((b) => !parseRef(b)).length;
}

export function trustLine(cfg: Pick<PluginConfig, "trustedSenders" | "trustedChats" | "stateDir">): string {
  const t = of(cfg);
  const users = userCount(t);
  if (!t.chats.size && !users) return "Trusted chats and users: none. Messages from anyone but you in a group count as a stranger's.";
  const held = [...t.chats.values()].filter(Boolean).length;
  let chats = `${t.chats.size} trusted chat${t.chats.size !== 1 ? "s" : ""}`;
  if (held) chats += ` (${held} hold reviews for you)`;
  return `Trusted: ${chats}, ${users} trusted user${users !== 1 ? "s" : ""}. ${TRUSTED_IS}`;
}

function clean(s: unknown, cap = 60): string {
  return Array.from(String(s), (c) => (/[\p{Cc}\p{Cf}]/u.test(c) ? "?" : c)).slice(0, cap).join("");
}

export function chatWarning(key: string, ownerOnly: boolean, openPlatform: boolean, cmd: Cmd): string {
  const platform = key.slice(0, key.indexOf(":"));
  const who = openPlatform
    ? `OpenClaw answers any group on ${platform} (channels.${platform}.groupPolicy is open), so everyone who can post ` +
      "in this chat, now and later, counts as someone you trust"
    : "Everyone who can post there, now and later, counts as someone you trust";
  const reviews = ownerOnly
    ? `Sentrook will hold its reviews for you: you answer them with ${cmd("allow")} from your direct message, the ` +
      "Control UI or the command line."
    : "Anyone OpenClaw lets answer an approval there may approve a review (narrow that with " +
      `channels.${platform}.execApprovals.approvers or commands.ownerAllowFrom in OpenClaw's config, or add the chat ` +
      `with ${OWNER_ONLY} to have reviews held for you).`;
  const flag = ownerOnly ? ` ${OWNER_ONLY}` : "";
  return (
    `Warning: ${who}. ${reviews} ${TRUSTED_IS} Trust a chat only on a private server where you know every member, ` +
    `never an open or public group. To trust it: ${cmd("trust-chat")} add ${key}${flag} --confirm`
  );
}

export function userWarning(key: string, cmd: Cmd): string {
  return (
    `Warning: messages from ${key} will count as from someone you trust, in any chat. ${TRUSTED_IS} ` +
    `To trust them: ${cmd("trust-user")} add ${key} --confirm`
  );
}

function usage(kind: "chat" | "user", cmd: Cmd): string {
  const c = cmd(`trust-${kind}`);
  const ref = kind === "chat" ? "<platform>:<chat id>" : "<platform>:<user id>";
  const extra = kind === "chat" ? ` [${OWNER_ONLY}]` : "";
  return `usage: ${c} add ${ref}${extra} [--confirm], ${c} remove ${ref} or ${c} list`;
}

function listText(cfg: Pick<PluginConfig, "trustedSenders" | "trustedChats" | "stateDir">, kind: "chat" | "user"): string {
  const t = of(cfg);
  const rows =
    kind === "chat"
      ? [...t.chats].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `- ${k}${v ? " (reviews held for you)" : ""}`)
      : [...new Set([...t.senders, ...[...t.bare].filter((b) => !parseRef(b))])].sort().map((k) => `- ${k}`);
  const head = trustLine(cfg);
  return rows.length ? [head, ...rows].join("\n") : head;
}

/** The chat a command was sent from, as far as the run says: its channel, and the ids of the owner's direct chat. */
export interface CommandChat {
  channel?: unknown;
  senderId?: unknown;
  sessionKey?: unknown;
}

/** The ids the command's own direct chat goes by on its channel (the peer in the session key, and the sender). */
function ownDirectIds(chat: CommandChat): { platform: string; ids: Set<string> } | null {
  const platform = typeof chat.channel === "string" ? chat.channel.trim().toLowerCase() : "";
  if (!platform) return null;
  const ids = new Set<string>();
  const key = typeof chat.sessionKey === "string" ? chat.sessionKey.trim().toLowerCase() : "";
  const m = /(?:^|:)(?:direct|dm):([^:]+)/.exec(key);
  if (m) ids.add(m[1]!);
  if (typeof chat.senderId === "string" && chat.senderId) {
    const s = chat.senderId.toLowerCase();
    ids.add(s);
    if (s.startsWith("user:")) ids.add(s.slice(5));
  }
  return { platform, ids };
}

export interface TrustResult {
  reply: string;
  change: Record<string, unknown> | null;
}

/**
 * `/sentrook-trust-chat ...` or `/sentrook-trust-user ...` (`kind` chat or user): the reply and the change record for
 * the traffic log (a `settings` record naming the platform only), or null when nothing changed. `chat` is the chat the
 * command was sent from (none on the command line); `hostConfig` is OpenClaw's config, for the louder warning on a
 * platform open to any group.
 */
export function run(
  cfg: Pick<PluginConfig, "trustedSenders" | "trustedChats" | "stateDir">,
  kind: "chat" | "user",
  rest: string,
  by: Entry,
  chat: CommandChat,
  hostConfig: unknown,
  now: Date,
  cmd: Cmd,
  beforeWrite: () => void,
): TrustResult {
  const words = rest.split(/\s+/).filter(Boolean);
  const flags = new Set(words.filter((w) => w.startsWith("--")));
  const args = words.filter((w) => !w.startsWith("--"));
  const allowed = kind === "chat" ? new Set(["--confirm", OWNER_ONLY]) : new Set(["--confirm"]);
  const unknown = [...flags].filter((f) => !allowed.has(f)).sort();
  if (unknown.length) return { reply: `Unknown option ${clean(unknown[0], 40)}.\n${usage(kind, cmd)}`, change: null };
  const op = (args[0] ?? "list").toLowerCase();
  if (op === "list" && args.length <= 1) return { reply: listText(cfg, kind), change: null };
  if ((op !== "add" && op !== "remove") || args.length !== 2) return { reply: usage(kind, cmd), change: null };
  const ref = parseRef(args[1]);
  if (ref === null) {
    return {
      reply:
        `"${clean(args[1])}" is not a ${kind} on a chat platform: write it as <platform>:<id>, for example ` +
        `discord:1234567890.\n${usage(kind, cmd)}`,
      change: null,
    };
  }
  const [platform, ident] = ref;
  const key = keyOf(ref);
  const lower = key.toLowerCase();
  const [field, listName, setting] =
    kind === "chat" ? (["chat", "trusted_chats", "trustedChats"] as const) : (["user", "trusted_senders", "trustedSenders"] as const);
  const configured =
    kind === "chat"
      ? fromConfig({ trustedChats: cfg.trustedChats }).chats.has(lower)
      : fromConfig({ trustedSenders: cfg.trustedSenders }).senders.has(lower);
  const record = { op: `trust_${kind}_${op}`, platform };

  if (op === "remove") {
    if (configured) return { reply: `${key} is set in the plugin config (${setting}); remove it there.`, change: null };
    return change(cfg.stateDir, (data) => {
      const items: unknown[] = Array.isArray(data[listName]) ? data[listName] : [];
      const kept = items.filter((e) => !(e && typeof e === "object" && String((e as Entry)[field]).toLowerCase() === lower));
      if (kept.length === items.length) return { reply: `${key} was not trusted by command. Nothing was changed.`, change: null };
      data[listName] = kept;
      const gone = kind === "chat" ? "its members' messages count as strangers' again" : "their messages count as a stranger's again";
      return { reply: `Removed ${key}: ${gone}.`, change: record };
    }, beforeWrite);
  }

  if (kind === "chat") {
    const own = ownDirectIds(chat);
    if (own && own.platform === platform && own.ids.has(ident.toLowerCase())) {
      return {
        reply:
          "This is your direct chat with the agent; a chat is trusted for a group's members. To trust a person, use " +
          `${cmd("trust-user")} add <platform>:<user id>. Nothing was changed.`,
        change: null,
      };
    }
  }
  const ownerOnly = flags.has(OWNER_ONLY);
  if (configured) {
    return { reply: `${key} is already trusted (${setting} in the plugin config; change it there). Nothing was changed.`, change: null };
  }
  if (!flags.has("--confirm")) {
    if (kind === "chat") {
      const open = (hostConfig as any)?.channels?.[platform]?.groupPolicy === "open";
      return { reply: chatWarning(key, ownerOnly, open, cmd), change: null };
    }
    return { reply: userWarning(key, cmd), change: null };
  }

  return change(cfg.stateDir, (data) => {
    const items: Entry[] = (Array.isArray(data[listName]) ? data[listName] : []).filter((e: unknown) => e && typeof e === "object");
    const same = items.filter((e) => String(e[field]).toLowerCase() === lower);
    if (same.length && (kind === "user" || (same[0]!.owner_only === true) === ownerOnly)) {
      return { reply: `${key} is already trusted. Nothing was changed.`, change: null };
    }
    if (!same.length && items.length >= MAX_ENTRIES) return { reply: `At most ${MAX_ENTRIES} can be trusted; remove one first.`, change: null };
    const entry: Entry = { [field]: key, set_at: `${now.toISOString().slice(0, 19)}Z`, set_by: by };
    if (kind === "chat") entry.owner_only = ownerOnly;
    data[listName] = [...items.filter((e) => !same.includes(e)), entry];
    const undo = `To undo: ${cmd(`trust-${kind}`)} remove ${key}.`;
    if (kind === "user") return { reply: `Trusted ${key}. ${TRUSTED_IS} ${undo}`, change: record };
    const reviews = ownerOnly ? "Its reviews are held for you." : "Its reviews are answered as OpenClaw allows there.";
    return { reply: `Trusted ${key}: its members' messages count as from someone you trust. ${reviews} ${undo}`, change: record };
  }, beforeWrite);
}

/** Reads, changes and writes the trust file under its lock. */
function change(stateDir: string, fn: (data: Entry) => TrustResult, beforeWrite: () => void): TrustResult {
  const file = path.join(stateDir, FILE);
  try {
    return withFileLock(file, () => {
      const store = new Store(stateDir);
      const data = store.loadTrust();
      if (data === null) return { reply: `The trust file ${file} could not be read; fix or remove it first.`, change: null };
      const out = fn(data);
      if (out.change) {
        beforeWrite();
        store.saveTrust(data);
      }
      return out;
    });
  } catch (err) {
    if (!(err instanceof LockTimeoutError)) throw err;
    return { reply: `The trust file ${file} is locked by another process; nothing was changed. Try again.`, change: null };
  }
}
