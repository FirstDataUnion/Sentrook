/**
 * The conversation a self-edit is judged against.
 *
 * OpenClaw's own background processes (see `selfEdit.ts`) read a conversation and then save to the agent's skills or
 * memory. The scanner judges such a save against what was actually said and done, so the plugin sends the part of the
 * conversation the save draws on as the PlanIR's top-level `self_edit` block:
 *
 *     {"kind": ..., "store": "memory" | "skills", "conversation": [entries, oldest first]}
 *
 * Where the entries come from:
 * - the run's own model context, `event.messages` on `before_prompt_build`: for the Skill Workshop review and the
 *   memory flush, a detached copy of the conversation they distil (`fromMessages`);
 * - the run's own tool results, from `after_tool_call` (`toolEntry`): what a review or a curator read on its way to
 *   the save. The run's own replies are not added: that is the process talking to itself.
 *
 * Entries:
 * - `{"role": "user", "turn", "sender", "text", "truncated"?}`. The sender comes from the host's own per-message
 *   owner flag (`__openclaw.senderIsOwner`): true is the owner, false someone else, absent unknown. Never from the
 *   message text.
 * - `{"role": "assistant", "turn", "text", "truncated"?}`, the agent's replies.
 * - `{"role": "tool", "turn", "tool", "arguments", "content", "excerpt_of_chars"?}`, a tool call and its result.
 *
 * Everything is redacted before it is stored. The log is capped at `LOG_MAX_ENTRIES` entries and about
 * `LOG_MAX_BYTES`: the oldest tool contents go first, then the oldest entries. `select` picks what a save carries.
 */

import { capArgs, capHeadTail, type Redactor } from "./redact.ts";

type Json = Record<string, any>;
export type Entry = Json;

/** Stored per user or assistant message, in characters, and per tool result, in bytes (head and tail). */
export const STORE_TEXT_CAP = 16 * 1024;
/** Stored per tool call's arguments, in bytes of JSON. */
export const ARGS_CAP_BYTES = 1024;
export const LOG_MAX_ENTRIES = 200;
export const LOG_MAX_BYTES = 400 * 1024;

/**
 * What a save carries: every user message (the most recent `USER_KEEP`), each cut to `USER_CAP` characters; the most
 * recent `ASSISTANT_KEEP` assistant messages, each cut to `ASSISTANT_CAP`; the `TOOL_TOP` tool results whose wording
 * overlaps most with what is saved and the `TOOL_RECENT` latest, each reduced to the `TOOL_WINDOW`-character window
 * with the most overlap; about `BLOCK_BUDGET` bytes in all.
 */
export const USER_CAP = 2000;
export const USER_KEEP = 30;
export const ASSISTANT_CAP = 1500;
export const ASSISTANT_KEEP = 20;
export const TOOL_WINDOW = 1500;
export const TOOL_TOP = 10;
export const TOOL_RECENT = 4;
export const BLOCK_BUDGET = 48 * 1024;

/** The keys whose values a save writes, also inside `operations` and `edits`; a patch's added lines in `input`. */
export const SAVE_TEXT_KEYS = ["content", "file_content", "new_string", "new_text", "newText"];
const NESTED_KEYS = ["operations", "edits"];

const WORD = /[a-z0-9_./@-]{4,}/g;

const OWNER = { relation: "owner", basis: ["host_owner_flag"] };
const OTHER = { relation: "other", basis: ["none"] };
const UNKNOWN = { relation: "unknown", basis: ["none"] };

const isRecord = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

/** The sender of a transcript user message, from the host's per-message owner flag only. */
export function senderOfMessage(m: Json): Json {
  const flag = isRecord(m.__openclaw) ? m.__openclaw.senderIsOwner : undefined;
  return flag === true ? OWNER : flag === false ? OTHER : UNKNOWN;
}

/** A message's text: a string, or its text blocks joined. */
export function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((b: any) => (b?.type === "text" && typeof b.text === "string" ? b.text : ""))
    .filter(Boolean)
    .join("\n");
}

// ---- the log ------------------------------------------------------------------------------------------------------

export function userEntry(turn: number, sender: Json, text: unknown, redactor: Redactor): Entry {
  const t = redactor.string(typeof text === "string" ? text : "");
  return { role: "user", turn, sender, text: t.slice(0, STORE_TEXT_CAP), chars: t.length };
}

export function assistantEntry(turn: number, text: unknown, redactor: Redactor): Entry | null {
  if (typeof text !== "string" || !text.trim()) return null;
  const t = redactor.string(text.trim());
  return { role: "assistant", turn, text: t.slice(0, STORE_TEXT_CAP), chars: t.length };
}

/** `redactedContent`: the result as the model saw it, already redacted. */
export function toolEntry(turn: number, tool: string, args: unknown, redactedContent: string, redactor: Redactor): Entry {
  return {
    role: "tool",
    turn,
    tool,
    arguments: capArgs(redactor.value(isRecord(args) ? args : { value: args }), ARGS_CAP_BYTES),
    content: capHeadTail(redactedContent, STORE_TEXT_CAP).text,
    chars: redactedContent.length,
  };
}

/**
 * The conversation in a run's model context (`event.messages`), as entries. User and assistant messages and tool
 * results are kept; host messages of other roles (runtime context, compaction summaries) are not. A tool result is
 * paired with its call's arguments from the assistant message that made it.
 */
export function fromMessages(messages: unknown, redactor: Redactor): Entry[] {
  if (!Array.isArray(messages)) return [];
  const out: Entry[] = [];
  const calls = new Map<string, { name: string; arguments: unknown }>();
  let turn = 0;
  for (const m of messages) {
    if (!isRecord(m)) continue;
    if (m.role === "user") {
      turn += 1;
      const text = textOf(m.content);
      if (text.trim()) out.push(userEntry(turn, senderOfMessage(m), text, redactor));
    } else if (m.role === "assistant") {
      const e = assistantEntry(Math.max(1, turn), textOf(m.content), redactor);
      if (e) out.push(e);
      for (const b of Array.isArray(m.content) ? m.content : []) {
        if (b?.type === "toolCall" && typeof b.id === "string") calls.set(b.id, { name: String(b.name ?? ""), arguments: b.arguments });
      }
    } else if (m.role === "toolResult") {
      const call = typeof m.toolCallId === "string" ? calls.get(m.toolCallId) : undefined;
      const tool = String(m.toolName ?? call?.name ?? "unknown");
      out.push(toolEntry(Math.max(1, turn), tool, call?.arguments ?? {}, redactor.string(textOf(m.content)), redactor));
    }
  }
  return trim(out);
}

const size = (e: Entry) => Buffer.byteLength(JSON.stringify(e), "utf8");

/** The rolling caps: the oldest tool contents are emptied first (the call stays), then the oldest entries go. */
export function trim(entries: Entry[]): Entry[] {
  entries = entries.slice(-LOG_MAX_ENTRIES);
  const sizes = entries.map(size);
  let total = sizes.reduce((a, b) => a + b, 0);
  for (let i = 0; total > LOG_MAX_BYTES && i < entries.length; i++) {
    const e = entries[i]!;
    if (e.role === "tool" && e.content) {
      entries[i] = { ...e, content: "" };
      const s = size(entries[i]!);
      total += s - sizes[i]!;
      sizes[i] = s;
    }
  }
  while (total > LOG_MAX_BYTES && entries.length) {
    total -= sizes.shift()!;
    entries.shift();
  }
  return entries;
}

// ---- the block ----------------------------------------------------------------------------------------------------

function words(text: string): Set<string> {
  return new Set(text.toLowerCase().match(WORD) ?? []);
}

/** The lines a patch adds, without their `+`. */
export function patchAdded(patch: string): string {
  return patch
    .split("\n")
    .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
    .map((l) => l.slice(1))
    .join("\n");
}

/** The text a save writes: `SAVE_TEXT_KEYS` values (also inside `operations` and `edits`) and a patch's added lines. */
export function saveText(value: unknown, depth = 0): string {
  if (depth > 8) return "";
  if (Array.isArray(value)) return value.map((v) => saveText(v, depth + 1)).join(" ");
  if (!isRecord(value)) return "";
  const out: string[] = SAVE_TEXT_KEYS.filter((k) => typeof value[k] === "string").map((k) => value[k]);
  if (typeof value.input === "string") out.push(patchAdded(value.input));
  for (const k of NESTED_KEYS) if (Array.isArray(value[k])) out.push(saveText(value[k], depth + 1));
  return out.filter(Boolean).join(" ");
}

/**
 * The `window`-character stretch of `text` holding the most distinct words of `want` (stepping by a quarter window;
 * the earliest on a tie), and how many it holds.
 */
export function excerpt(text: string, want: Set<string>, window = TOOL_WINDOW): [string, number] {
  const count = (s: string) => [...words(s)].filter((w) => want.has(w)).length;
  if (text.length <= window) return [text, count(text)];
  const lower = text.toLowerCase();
  const hits: Array<[number, number, string]> = [];
  for (const m of lower.matchAll(WORD)) if (want.has(m[0])) hits.push([m.index!, m.index! + m[0].length, m[0]]);
  const starts: number[] = [];
  for (let s = 0; s <= text.length - window; s += Math.floor(window / 4)) starts.push(s);
  if (starts[starts.length - 1] !== text.length - window) starts.push(text.length - window);
  let best = -1;
  let at = 0;
  for (const start of starts) {
    const n = new Set(hits.filter(([s, e]) => s >= start && e <= start + window).map(([, , w]) => w)).size;
    if (n > best) {
      best = n;
      at = start;
    }
  }
  return [text.slice(at, at + window), best];
}

const publicOf = (e: Entry): Entry => Object.fromEntries(Object.entries(e).filter(([k]) => !k.startsWith("_") && k !== "chars"));

/**
 * The conversation a save carries, in conversation order:
 * - every user message (the most recent `USER_KEEP`), cut to `USER_CAP` (`truncated: true` when cut);
 * - the most recent `ASSISTANT_KEEP` assistant messages, cut to `ASSISTANT_CAP`;
 * - the `TOOL_TOP` tool results whose wording overlaps most with the saved text (results with no overlap are not
 *   ranked; the later one wins a tie) and the `TOOL_RECENT` latest, each reduced to its `excerpt`
 *   (`excerpt_of_chars`: the full length, when it is an excerpt);
 * then, while over about `BLOCK_BUDGET` bytes, the oldest assistant and tool entries are dropped, and the oldest user
 * messages only if still over.
 */
export function select(entries: Entry[], saveArgs: unknown): Entry[] {
  const want = words(saveText(saveArgs));
  const idx = (role: string) => entries.map((e, i) => (e.role === role ? i : -1)).filter((i) => i >= 0);
  const users = idx("user").slice(-USER_KEEP);
  const assistants = idx("assistant").slice(-ASSISTANT_KEEP);
  const tools = idx("tool");
  const scored = new Map(tools.map((i) => [i, excerpt(String(entries[i]!.content ?? ""), want)] as const));
  const ranked = tools.filter((i) => scored.get(i)![1] > 0).sort((a, b) => scored.get(b)![1] - scored.get(a)![1] || b - a);
  const keep = new Set([...users, ...assistants, ...ranked.slice(0, TOOL_TOP), ...tools.slice(-TOOL_RECENT)]);

  const out: Entry[] = [];
  for (const i of [...keep].sort((a, b) => a - b)) {
    const e = entries[i]!;
    if (e.role === "user" || e.role === "assistant") {
      const cap = e.role === "user" ? USER_CAP : ASSISTANT_CAP;
      const text = String(e.text ?? "");
      const full = Math.max(Number(e.chars ?? 0), text.length);
      out.push({ ...publicOf(e), text: text.slice(0, cap), ...(full > cap ? { truncated: true } : {}) });
    } else {
      const text = scored.get(i)![0];
      const full = Math.max(Number(e.chars ?? 0), String(e.content ?? "").length);
      out.push({ ...publicOf(e), content: text, ...(full > text.length ? { excerpt_of_chars: full } : {}) });
    }
  }

  const sizes = out.map(size);
  let total = sizes.reduce((a, b) => a + b, 0);
  for (const roles of [["assistant", "tool"], ["user"]]) {
    let i = 0;
    while (total > BLOCK_BUDGET && i < out.length) {
      if (roles.includes(out[i]!.role)) {
        total -= sizes.splice(i, 1)[0]!;
        out.splice(i, 1);
      } else {
        i += 1;
      }
    }
  }
  return out;
}

export function block(kind: string, store: string, entries: Entry[], saveArgs: unknown): Json {
  return { kind, store, conversation: select(entries, saveArgs) };
}
