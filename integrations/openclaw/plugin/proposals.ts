/**
 * The agent's setup proposals: the `sentrook_propose_setup` tool.
 *
 * The agent learns from the owner what is routine (a folder they work in, a service they are about to use, the name
 * of a key) that the plugin cannot find in config or traffic. This tool lets it add those to the owner's setup screen
 * (`/sentrook-setup`, `setup.ts`) instead of handing the owner commands described in its own words. It sets nothing:
 * the owner reads each item there, in the plugin's words, and sets it with the screen's code.
 *
 * **What it takes.** Up to `MAX_ITEMS` items, each one of:
 * - a grant, `{kind, pattern, allows?, expires?, follow?, reason}` (kind destination, file, provider, repo, credential
 *   or folder; `follow` is for a folder in a git repository, such as `origin/main`);
 * - a channel binding, `{binding, reason}`;
 * - a trusted chat, `{trusted_chat, owner_only?, reason}`, or a trusted user, `{trusted_sender, reason}`, each as
 *   `<platform>:<id>` (trust.ts); the setup screen shows each with its warning, and applying it trusts it as
 *   `/sentrook-trust-chat add` / `/sentrook-trust-user add` would.
 * Each `reason` is one sentence of at most `MAX_REASON` characters, shown to the owner only as a quoted note. Each
 * item is checked by the code the owner's own commands use: a grant must be one `grant <kind> <pattern> --persistent
 * [--allows ...] [--expires ...] [--follow ...]` would accept (`grants.parseGrant`), a binding one `bind add` would add that could
 * ever apply (`planir.bindingProblem`), and either must be one the setup screen can show (`setup.proposalItem`,
 * `setup.validItem`). An item that fails comes back to the agent with that code's error; the others are stored.
 * Session grants are refused (setup is for lasting grants, or ones with an expiry), and so are settings: the setup
 * screen shows grants and bindings only, the owner changes settings with their own commands, and attended platforms
 * are never proposed. A credential grant names the key, never its value.
 *
 * **Where it goes.** `<state>/proposals.json`, locked like the grants file: an id `p-` and six hex digits, the session
 * ref, when it was made and when it expires (`setup.PROPOSAL_TTL_MS`, a day). At most `MAX_OPEN` proposals are open;
 * a new one replaces the oldest. The agent hears only how many items were added and to ask the owner to open the
 * setup screen (and which items were not added, with why): never the screen, its evidence, its warnings or its code.
 *
 * **Who may call it** is decided as for the setup report (`setupReport.reportAllowed`, `setupReport.Markers`): only
 * the owner, in a run started by their own message in a direct chat. Everywhere else the answer is
 * `setupReport.REFUSAL` and nothing is stored. The Hermes plugin takes the same items, text for text.
 */

import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import path from "node:path";

import { destinationOk, resolveStateDir } from "./config.ts";
import * as folders from "./folders.ts";
import * as grants from "./grants.ts";
import { bindingProblem } from "./planir.ts";
import { createRedactor } from "./redact.ts";
import * as setup from "./setup.ts";
import { LockTimeoutError, readTime, Store, withFileLock } from "./store.ts";
import * as trust from "./trust.ts";

type Entry = Record<string, any>;
type Cmd = (sub: string) => string;

export const TOOL = "sentrook_propose_setup";
/** Items in one call. */
export const MAX_ITEMS = 20;
/** Characters in one item's reason. */
export const MAX_REASON = 200;
/** Proposals open at once; a new one replaces the oldest. */
export const MAX_OPEN = 3;

const GRANT_FIELDS = new Set(["kind", "pattern", "allows", "expires", "follow", "reason", "scope"]);
const BINDING_FIELDS = new Set(["binding", "reason"]);
const TRUSTED_CHAT_FIELDS = new Set(["trusted_chat", "owner_only", "reason"]);
const TRUSTED_SENDER_FIELDS = new Set(["trusted_sender", "reason"]);

export const NO_ITEMS = "Give items: a list of 1 to 20 grants or channel bindings, each with a reason. Nothing was added.";
export const TOO_MANY = `At most ${MAX_ITEMS} items in one proposal. Nothing was added.`;
export const NOT_SAVED = "Sentrook could not save the proposal. Nothing was added.";

const NOT_AN_ITEM =
  "Not an item: give a grant (kind, pattern, reason), a channel binding (binding, reason), a trusted chat " +
  "(trusted_chat, reason) or a trusted user (trusted_sender, reason).";
const BAD_TRUSTED =
  "A trusted chat or user is <platform>:<id> as the chat app names it, such as discord:1234567890, on a " +
  "chat platform.";
const BAD_OWNER_ONLY = "owner_only is true or false.";
const SETTING = "Settings are not proposed: the owner changes them with their own commands; explain the setting to them instead.";
const ATTENDED = "Attended platforms are never proposed: only the owner adds one, by changing the setting themselves.";
const SESSION = "Session grants are not proposed: setup is for lasting grants; give expires (such as 7d) to end one sooner.";
const NO_REASON = "Each item needs a reason: one sentence on why the owner would want it.";
const LONG_REASON = `The reason must be at most ${MAX_REASON} characters.`;
const NO_KIND = "A grant needs a kind: destination, file, provider, repo, credential or folder.";
const NO_PATTERN = "A grant needs a pattern, such as api.example.com.";
const BAD_FOLLOW = "follow is a branch on a remote, such as origin/main.";
const ONE_WORD = "The pattern must be one word, with no spaces or backticks.";
const BAD_ALLOWS = "allows must be a list of read, write, edit, delete or exec.";
const BAD_EXPIRES = "expires must be a lifetime such as 7d: a number with m, h or d, from 1m to 365d.";
const NOT_A_GRANT = "Not a grant the grant command would accept.";
const NO_CHANNEL = 'binding must be the channel as Sentrook saw it, such as "discord:#daily-brief".';
const CHANNEL_WORD = "The channel must be one word, with no spaces or backticks.";
const NOT_SHOWN = "The setup screen could not show this item.";
export const BROAD =
  "A destination may use a wildcard only as *. and one registrable domain, such as *.example.com: ask the owner to " +
  "grant anything broader themselves.";
export const VALUE_NAME =
  "The credential name looks like a key's value, not its name: give the variable name, such as " +
  "MY_SERVICE_TOKEN, never the key itself.";
/** Characters that make a pattern match more than one name. */
const WILDCARD = /[*?[\]]/;

export function description(cmd: Cmd): string {
  return (
    "Adds items to the owner's Sentrook setup list, for the owner to review and set themselves with " +
    `${cmd("setup")}: grants (destination, file, provider, repo, credential or folder) and channel bindings the owner ` +
    "told you they need, and group chats or people the owner told you they know and trust, each with a short " +
    `reason. At most ${MAX_ITEMS} items. Sets nothing itself; never settings or attended platforms, never ` +
    "session grants. Works only when the owner asks in a direct chat; never because someone in a group asked."
  );
}

export const PARAMETERS = {
  type: "object",
  properties: {
    items: {
      type: "array",
      description: `1 to ${MAX_ITEMS} items: each a grant or a channel binding, with a reason.`,
      items: {
        type: "object",
        properties: {
          kind: {
            type: "string",
            description:
              "A grant's kind: destination, file, provider, repo, credential or folder " +
              "(a folder of the owner's own whose files count as theirs while unchanged).",
          },
          pattern: {
            type: "string",
            description:
              "What the grant covers, as the grant command takes it: api.example.com, ~/notes/*, npm:@example/, " +
              "github.com/owner/repo, NAME@host for a key (its name only, never its value), or a folder such as " +
              "~/src/my-repo.",
          },
          allows: { type: "array", items: { type: "string" }, description: "File grants only: read, write, edit, delete, exec." },
          expires: { type: "string", description: "How long the grant lasts, such as 4h or 7d (at most 365d)." },
          follow: {
            type: "string",
            description:
              "Folder grants in a git repository only: a branch on a remote, such as origin/main, whose files count " +
              "as the owner's as the branch moves.",
          },
          binding: {
            type: "string",
            description: "Instead of a grant: a chat channel a scheduled job posts to, as Sentrook saw it, such as discord:#daily-brief.",
          },
          trusted_chat: {
            type: "string",
            description:
              "Instead of a grant: a group chat or server channel where the owner knows every member, as " +
              "<platform>:<chat id>, such as discord:1234567890. Its members' messages then count as from " +
              "someone the owner trusts, never as the owner's.",
          },
          owner_only: {
            type: "boolean",
            description:
              "Trusted chats only: true holds the chat's reviews for the owner instead of letting members answer them.",
          },
          trusted_sender: {
            type: "string",
            description:
              "Instead of a grant: a person the owner knows, as <platform>:<user id>. Their messages then count as " +
              "from someone the owner trusts, never as the owner's.",
          },
          reason: {
            type: "string",
            description: `Why the owner would want it, in one sentence of at most ${MAX_REASON} characters.`,
          },
        },
        required: ["reason"],
      },
    },
  },
  required: ["items"],
  additionalProperties: false,
} as const;

// ---- checking the items ---------------------------------------------------------------------------------------------

function clean(s: unknown, cap: number): string {
  return Array.from(String(s), (c) => (grants.printable(c) ? c : "?"))
    .slice(0, cap)
    .join("");
}

const hasSpace = (s: string) => /\s/u.test(s);
const word = (s: unknown): s is string => typeof s === "string" && s.length > 0 && !hasSpace(s) && !s.includes("`");
const has = (o: Entry, k: string) => Object.hasOwn(o, k);

/** One item as it is stored, or why it is refused. */
export function checkItem(raw: unknown): Entry | string {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return NOT_AN_ITEM;
  const r = raw as Entry;
  if (has(r, "setting")) return typeof r.setting === "string" && r.setting.toLowerCase().includes("attended") ? ATTENDED : SETTING;
  if (has(r, "attended") || (typeof r.kind === "string" && r.kind.trim().toLowerCase() === "attended")) return ATTENDED;
  if ((has(r, "scope") && r.scope !== "persistent") || has(r, "session") || has(r, "session_ref")) return SESSION;
  if (has(r, "trusted_chat") || has(r, "trusted_sender")) return trustedItem(r);
  const binding = has(r, "binding");
  const fields = binding ? BINDING_FIELDS : GRANT_FIELDS;
  const unknown = Object.keys(r)
    .filter((k) => !fields.has(k))
    .sort();
  if (unknown.length) {
    const takes = binding ? "a channel binding takes binding and reason" : "a grant takes kind, pattern, allows, expires, follow and reason";
    return `Unknown field "${clean(unknown[0], 40)}": ${takes}.`;
  }
  const reason = r.reason;
  if (typeof reason !== "string" || !reason.trim()) return NO_REASON;
  if ([...reason].length > MAX_REASON) return LONG_REASON;
  const stored = binding ? bindingItem(r.binding) : grantItem(r);
  if (typeof stored === "string") return stored;
  stored.reason = reason;
  const shown = setup.proposalItem(stored);
  if (!shown || !setup.validItem(shown)) return NOT_SHOWN;
  return stored;
}

/** A trusted chat or user as `/sentrook-trust-chat add` / `/sentrook-trust-user add` takes it. */
function trustedItem(r: Entry): Entry | string {
  const chat = has(r, "trusted_chat");
  const fields = chat ? TRUSTED_CHAT_FIELDS : TRUSTED_SENDER_FIELDS;
  const unknown = Object.keys(r)
    .filter((k) => !fields.has(k))
    .sort();
  if (unknown.length) {
    const takes = chat ? "a trusted chat takes trusted_chat, owner_only and reason" : "a trusted user takes trusted_sender and reason";
    return `Unknown field "${clean(unknown[0], 40)}": ${takes}.`;
  }
  const reason = r.reason;
  if (typeof reason !== "string" || !reason.trim()) return NO_REASON;
  if ([...reason].length > MAX_REASON) return LONG_REASON;
  const name = chat ? "trusted_chat" : "trusted_sender";
  const ref = trust.parseRef(r[name]);
  if (ref === null) return BAD_TRUSTED;
  const stored: Entry = { [name]: ref.join(":"), reason };
  if (chat && has(r, "owner_only")) {
    if (typeof r.owner_only !== "boolean") return BAD_OWNER_ONLY;
    stored.owner_only = r.owner_only;
  }
  const shown = setup.proposalItem(stored);
  if (!shown || !setup.validItem(shown)) return NOT_SHOWN;
  return stored;
}

/** A channel binding as `bind add` takes it, that could ever relieve a send. */
function bindingItem(channel: unknown): Entry | string {
  if (typeof channel !== "string" || !channel) return NO_CHANNEL;
  if ([...channel].length > grants.MAX_PATTERN || !grants.printable(channel)) {
    return `The channel must be at most ${grants.MAX_PATTERN} printable characters.`;
  }
  if (!word(channel)) return CHANNEL_WORD;
  const problem = bindingProblem(channel);
  if (problem) return `This channel binding would never apply: ${problem}.`;
  return { binding: true, pattern: channel };
}

/** A grant as `grant <kind> <pattern> --persistent [--allows ...] [--expires ...]` takes it. */
function grantItem(r: Entry): Entry | string {
  const { kind, pattern, allows, expires, follow } = r;
  if (typeof kind !== "string" || !kind || hasSpace(kind)) return NO_KIND;
  if (typeof pattern !== "string" || !pattern) return NO_PATTERN;
  if (!word(pattern)) return ONE_WORD;
  const words = [kind, pattern, "--persistent"];
  if (allows !== undefined && allows !== null) {
    if (!Array.isArray(allows) || !allows.every((a) => typeof a === "string" && a && !/[\s,]/u.test(a))) return BAD_ALLOWS;
    words.push(`--allows=${allows.join(",")}`);
  }
  if (expires !== undefined && expires !== null) {
    if (typeof expires !== "string" || hasSpace(expires)) return BAD_EXPIRES;
    words.push(`--expires=${expires}`);
  }
  if (follow !== undefined && follow !== null) {
    if (typeof follow !== "string" || !follow || hasSpace(follow)) return BAD_FOLLOW;
    words.push(`--follow=${follow}`);
  }
  // The agent's own, stricter rule first: the grant command's refusal would offer it forms it may not propose.
  if (kind.toLowerCase() === "destination" && tooBroad(pattern)) return BROAD;
  const parsed = grants.parseGrant(words.join(" "), (sub) => sub);
  if (typeof parsed === "string") return parsed || NOT_A_GRANT;
  if (parsed.kind === "credential" && valueShaped(parsed.pattern.slice(0, parsed.pattern.indexOf("@")))) return VALUE_NAME;
  const out: Entry = { kind: parsed.kind, pattern: parsed.pattern };
  if (parsed.kind === "folder") {
    // The folder must be one the owner could trust now, named as Sentrook will record it.
    let real: string;
    try {
      real = folders.resolve(parsed.pattern, { home: homedir(), stateDir: resolveStateDir(process.env) });
      if (parsed.follow && folders.gitTop(real) === null) return "--follow needs a git repository; this folder is not in one.";
    } catch (err) {
      if (err instanceof folders.FolderError) return err.message;
      throw err;
    }
    out.pattern = `${real}/`;
    if (parsed.follow) out.follow = parsed.follow;
  }
  if (parsed.allows?.length) out.allows = parsed.allows;
  if (expires !== undefined && expires !== null) out.expires = expires;
  return out;
}

/**
 * A destination the agent may not propose: a wildcard anywhere but as `*.` and a domain the grant command takes
 * (`config.destinationOk`: one registrable domain, or a name that never resolves on the public internet). Only the
 * owner may put a wildcard in a channel's name or before an `@`.
 */
function tooBroad(pattern: string): boolean {
  return (
    WILDCARD.test(pattern) && (!pattern.startsWith("*.") || WILDCARD.test(pattern.slice(2)) || !destinationOk(pattern))
  );
}

/** A credential name that the plugin's redactor would take for a secret value (a token's own shape). */
function valueShaped(name: string): boolean {
  return createRedactor("standard", "").string(name) !== name;
}

export type Checked = { ok: Entry[]; refused: Array<[number, string]> } | string;

/**
 * The stored items and, for those refused, their numbers and why; or why the whole call is refused. Items sent as
 * JSON text read as the list it holds.
 */
export function check(args: unknown): Checked {
  let items = args && typeof args === "object" && !Array.isArray(args) ? (args as Entry).items : undefined;
  if (typeof items === "string") {
    try {
      items = JSON.parse(items);
    } catch {
      items = undefined;
    }
  }
  if (!Array.isArray(items) || !items.length) return NO_ITEMS;
  if (items.length > MAX_ITEMS) return TOO_MANY;
  const ok: Entry[] = [];
  const refused: Array<[number, string]> = [];
  items.forEach((raw, i) => {
    const got = checkItem(raw);
    if (typeof got === "string") refused.push([i + 1, got]);
    else ok.push(got);
  });
  return { ok, refused };
}

/** What the agent hears: how many were added and where the owner reviews them, and the items not added. */
export function reply(added: number, refused: Array<[number, string]>, cmd: Cmd): string {
  const lines = added
    ? [
        `Added ${added} item${added === 1 ? "" : "s"} to Sentrook's setup list. Ask the owner to send ` +
          `${cmd("setup")} to review ${added === 1 ? "it" : "them"}.`,
      ]
    : ["Nothing was added to Sentrook's setup list."];
  if (refused.length) {
    const n = refused.length;
    lines.push(`${n} item${n === 1 ? "" : "s"} not added:`);
    for (const [i, why] of refused) lines.push(`- Item ${i}: ${why}`);
  }
  return lines.join("\n");
}

// ---- storing them ---------------------------------------------------------------------------------------------------

export const newId = () => `p-${randomBytes(3).toString("hex")}`;
const iso = (d: Date) => `${d.toISOString().slice(0, 19)}Z`;

/**
 * Stores a proposal of `items` from the session `ref`: its id and the ids of the open proposals it replaced. Expired
 * proposals are dropped. `unchecked`: the chat had read content no scan had seen yet when the agent proposed it. Null
 * when the proposals file cannot be read, so nothing in it is overwritten.
 */
export function save(
  stateDir: string,
  items: Entry[],
  ref: string,
  now: Date,
  makeId: () => string = newId,
  unchecked = false,
): { id: string; replaced: string[] } | null {
  const store = new Store(stateDir);
  try {
    return withFileLock(path.join(stateDir, "proposals.json"), () => {
      const raw = store.loadProposals();
      if (raw === null) return null;
      const taken = new Set(raw.proposals.map((p) => (p && typeof p === "object" ? (p as Entry).id : undefined)));
      let id = makeId();
      while (taken.has(id)) id = makeId();
      // Oldest first; proposals made in the same second stay in the order they were stored.
      const live = setup.liveProposals(raw, now).sort((a, b) => readTime(a.created_at)!.getTime() - readTime(b.created_at)!.getTime());
      const replaced: string[] = [];
      while (live.length >= MAX_OPEN) replaced.push(live.shift()!.id);
      live.push({
        id,
        session_ref: ref,
        created_at: iso(now),
        expires_at: iso(new Date(now.getTime() + setup.PROPOSAL_TTL_MS)),
        items,
        ...(unchecked ? { unchecked: true } : {}),
      });
      raw.proposals = live;
      store.saveProposals(raw);
      return { id, replaced };
    });
  } catch (err) {
    if (err instanceof LockTimeoutError) return null;
    throw err;
  }
}

/** The tool's answer to a call whose arguments `check` gave `checked`, from the session `ref`, and what the traffic log records of it. */
export function propose(
  stateDir: string,
  checked: Checked,
  ref: string,
  now: Date,
  cmd: Cmd,
  makeId: () => string = newId,
  unchecked = false,
): { text: string; logged: Entry } {
  if (typeof checked === "string") return { text: checked, logged: { outcome: "refused", reason: "invalid", items: 0 } };
  const { ok, refused } = checked;
  const log = { items: ok.length, rejected: refused.length };
  if (!ok.length) return { text: reply(0, refused, cmd), logged: { outcome: "none", ...log } };
  const saved = save(stateDir, ok, ref, now, makeId, unchecked);
  if (saved === null) return { text: NOT_SAVED, logged: { outcome: "error", reason: "proposals file unreadable", ...log } };
  return {
    text: reply(ok.length, refused, cmd),
    logged: {
      outcome: "stored",
      proposal: saved.id,
      ...(unchecked ? { unchecked: true } : {}),
      ...(saved.replaced.length ? { replaced: saved.replaced } : {}),
      ...log,
    },
  };
}
