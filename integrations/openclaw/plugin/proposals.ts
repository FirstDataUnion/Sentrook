/**
 * The agent's setup proposals: the `sentrook_propose_setup` tool.
 *
 * The agent learns from the owner what is routine (a folder they work in, a service they are about to use, the name
 * of a key) that the plugin cannot find in config or traffic. This tool lets it add those to the owner's setup screen
 * (`/sentrook-setup`, `setup.ts`) instead of handing the owner commands described in its own words. It sets nothing:
 * the owner reads each item there, in the plugin's words, and sets it with the screen's code.
 *
 * **What it takes.** Up to `MAX_ITEMS` items, each one of:
 * - a grant, `{kind, pattern, allows?, expires?, reason}` (kind destination, file, provider, repo or credential);
 * - a channel binding, `{binding, reason}`.
 * Each `reason` is one sentence of at most `MAX_REASON` characters, shown to the owner only as a quoted note. Each
 * item is checked by the code the owner's own commands use: a grant must be one `grant <kind> <pattern> --persistent
 * [--allows ...] [--expires ...]` would accept (`grants.parseGrant`), a binding one `bind add` would add that could
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
import path from "node:path";

import * as grants from "./grants.ts";
import { bindingProblem } from "./planir.ts";
import * as setup from "./setup.ts";
import { LockTimeoutError, readTime, Store, withFileLock } from "./store.ts";

type Entry = Record<string, any>;
type Cmd = (sub: string) => string;

export const TOOL = "sentrook_propose_setup";
/** Items in one call. */
export const MAX_ITEMS = 20;
/** Characters in one item's reason. */
export const MAX_REASON = 200;
/** Proposals open at once; a new one replaces the oldest. */
export const MAX_OPEN = 3;

const GRANT_FIELDS = new Set(["kind", "pattern", "allows", "expires", "reason", "scope"]);
const BINDING_FIELDS = new Set(["binding", "reason"]);

export const NO_ITEMS = "Give items: a list of 1 to 20 grants or channel bindings, each with a reason. Nothing was added.";
export const TOO_MANY = `At most ${MAX_ITEMS} items in one proposal. Nothing was added.`;
export const NOT_SAVED = "Sentrook could not save the proposal. Nothing was added.";

const NOT_AN_ITEM = "Not an item: give a grant (kind, pattern, reason) or a channel binding (binding, reason).";
const SETTING = "Settings are not proposed: the owner changes them with their own commands; explain the setting to them instead.";
const ATTENDED = "Attended platforms are never proposed: only the owner adds one, by changing the setting themselves.";
const SESSION = "Session grants are not proposed: setup is for lasting grants; give expires (such as 7d) to end one sooner.";
const NO_REASON = "Each item needs a reason: one sentence on why the owner would want it.";
const LONG_REASON = `The reason must be at most ${MAX_REASON} characters.`;
const NO_KIND = "A grant needs a kind: destination, file, provider, repo or credential.";
const NO_PATTERN = "A grant needs a pattern, such as api.example.com.";
const ONE_WORD = "The pattern must be one word, with no spaces or backticks.";
const BAD_ALLOWS = "allows must be a list of read, write, edit, delete or exec.";
const BAD_EXPIRES = "expires must be a lifetime such as 7d: a number with m, h or d, from 1m to 365d.";
const NOT_A_GRANT = "Not a grant the grant command would accept.";
const NO_CHANNEL = 'binding must be the channel as Sentrook saw it, such as "discord:#daily-brief".';
const CHANNEL_WORD = "The channel must be one word, with no spaces or backticks.";
const NOT_SHOWN = "The setup screen could not show this item.";

export function description(cmd: Cmd): string {
  return (
    "Adds items to the owner's Sentrook setup list, for the owner to review and set themselves with " +
    `${cmd("setup")}: grants (destination, file, provider, repo or credential) and channel bindings the owner ` +
    `told you they need, each with a short reason. At most ${MAX_ITEMS} items. Sets nothing itself; never ` +
    "settings or attended platforms, never session grants. Works only when the owner asks in a direct chat."
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
          kind: { type: "string", description: "A grant's kind: destination, file, provider, repo or credential." },
          pattern: {
            type: "string",
            description:
              "What the grant covers, as the grant command takes it: api.example.com, ~/notes/*, npm:@example/, " +
              "github.com/owner/repo, or NAME@host for a key (its name only, never its value).",
          },
          allows: { type: "array", items: { type: "string" }, description: "File grants only: read, write, edit, delete, exec." },
          expires: { type: "string", description: "How long the grant lasts, such as 4h or 7d (at most 365d)." },
          binding: {
            type: "string",
            description: "Instead of a grant: a chat channel a scheduled job posts to, as Sentrook saw it, such as discord:#daily-brief.",
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
  const binding = has(r, "binding");
  const fields = binding ? BINDING_FIELDS : GRANT_FIELDS;
  const unknown = Object.keys(r)
    .filter((k) => !fields.has(k))
    .sort();
  if (unknown.length) {
    const takes = binding ? "a channel binding takes binding and reason" : "a grant takes kind, pattern, allows, expires and reason";
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
  const { kind, pattern, allows, expires } = r;
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
  const parsed = grants.parseGrant(words.join(" "), (sub) => sub);
  if (typeof parsed === "string") return parsed || NOT_A_GRANT;
  const out: Entry = { kind: parsed.kind, pattern: parsed.pattern };
  if (parsed.allows?.length) out.allows = parsed.allows;
  if (expires !== undefined && expires !== null) out.expires = expires;
  return out;
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
 * proposals are dropped. Null when the proposals file cannot be read, so nothing in it is overwritten.
 */
export function save(stateDir: string, items: Entry[], ref: string, now: Date, makeId: () => string = newId): { id: string; replaced: string[] } | null {
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
export function propose(stateDir: string, checked: Checked, ref: string, now: Date, cmd: Cmd, makeId: () => string = newId): { text: string; logged: Entry } {
  if (typeof checked === "string") return { text: checked, logged: { outcome: "refused", reason: "invalid", items: 0 } };
  const { ok, refused } = checked;
  const log = { items: ok.length, rejected: refused.length };
  if (!ok.length) return { text: reply(0, refused, cmd), logged: { outcome: "none", ...log } };
  const saved = save(stateDir, ok, ref, now, makeId);
  if (saved === null) return { text: NOT_SAVED, logged: { outcome: "error", reason: "proposals file unreadable", ...log } };
  return {
    text: reply(ok.length, refused, cmd),
    logged: { outcome: "stored", proposal: saved.id, ...(saved.replaced.length ? { replaced: saved.replaced } : {}), ...log },
  };
}
