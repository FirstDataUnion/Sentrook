/**
 * Owner-only commands: who may run a command that changes how Sentrook behaves.
 *
 * OpenClaw tells a command handler whether the sender is the owner (`senderIsOwner`) and gives it
 * `assertOwnerCurrent`, which throws once that authority is gone, but only when the command declares
 * `requiredScopes`. Owner commands therefore declare `operator.admin`, and the host lets two kinds of sender run
 * them:
 * - the owner on a chat channel, from their own direct message: a sender listed in `commands.ownerAllowFrom` (when
 *   the list is empty, OpenClaw fills it with the sender of the first pairing approval) or linked to an admin
 *   operator profile. A chat sender holds no gateway scopes; the host lets the owner past the missing scope;
 * - a gateway client holding `operator.admin`, such as the owner's default Control UI connection. Limited Control UI
 *   sessions and write-only CLI clients are refused by the host before the handler runs.
 * Inside the handler the owner is `senderIsOwner === true` with `assertOwnerCurrent` present and passing; the
 * command calls `gate.beforeWrite()` before each write, so an owner demoted mid-command writes nothing more.
 *
 * OpenClaw decides the owner by the sender, not the room: the owner's own message in a group or channel room counts
 * as the owner's too, and OpenClaw writes the command and its reply into that room's session transcript. So every
 * owner command also refuses a group or channel room, the agent's main session while OpenClaw routes rooms into it
 * (from the Control UI too), and a chat on a chat channel it cannot tell from a room (no session key): its reply
 * (scans, hosts, file paths, reasons, grants) would be shown to everyone there.
 *
 * Anyone holding the shared gateway token has `operator.admin` and so counts as the owner. Control UI
 * connections carry no sender id, so their audit records show the basis, not a name.
 *
 * Warning for installers: an entry in `commands.ownerAllowFrom` that matches no one locks unlisted
 * non-admin clients out of every plugin command ("requires authorization"). The plugin cannot see the
 * sender roster, so it cannot check those entries for you.
 *
 * Every attempt, allowed or refused, is written to the traffic log as a `command` record (none when
 * the owner has turned the traffic log off). A sender id, when there is one, is stored only as a
 * salted hash.
 */

import { createHmac } from "node:crypto";

import { channelOf, chatKindOfTurn, GROUP_SEGMENT, mainSharedWithRooms } from "./planir.ts";

export const OWNER_SCOPES = ["operator.admin"];

/** The fields of OpenClaw's command context the owner check reads. */
export interface OwnerContext {
  senderId?: unknown;
  channel?: string;
  senderIsOwner?: unknown;
  assertOwnerCurrent?: () => void;
  gatewayClientScopes?: unknown;
  /** The session the command was sent in and its reply addresses, which say whether the chat is a room. */
  sessionKey?: unknown;
  from?: unknown;
  to?: unknown;
}

export interface OwnerAudit {
  traffic: { write: (record: Record<string, unknown>) => void };
  salt: () => string;
}

export interface OwnerGate {
  owner: boolean;
  basis: string[];
  /** Why the sender was refused: `not_owner`, `stale_owner`, `group_chat` or `unknown_chat`. */
  reason?: string;
  /** Call before each write; throws `OwnerRefused` (and audits it) once the sender is no longer the owner. */
  beforeWrite: () => void;
}

export class OwnerRefused extends Error {}

export function senderRef(senderId: unknown, salt: string): string | null {
  return typeof senderId === "string" && senderId ? `u_${createHmac("sha256", salt).update(senderId).digest("hex").slice(0, 16)}` : null;
}

/** Where an owner command runs, for refusals and help. */
export const OWNER_ROUTES =
  "from the owner's own direct message to the agent (a sender in commands.ownerAllowFrom, which the first pairing " +
  "approval fills), from the Control UI, or as openclaw sentrook <command> on the machine";

export function refusal(verb: string): string {
  return (
    `Only the owner can run /sentrook ${verb}: send /sentrook-${verb} ${OWNER_ROUTES}. A group chat or server ` +
    "channel, even a private one, never runs it."
  );
}

/** The reply to the owner's command in a room, in a session a room shares, or in a chat Sentrook cannot tell from one. */
export function roomRefusal(verb: string): string {
  return (
    `/sentrook-${verb} only runs in your own direct message with the agent, the Control UI (in a session no room ` +
    `shares) or as openclaw sentrook ${verb} on the machine. This chat is a group or server channel (private ones ` +
    "too), shares a session with one, or Sentrook cannot tell, so anyone there could see the reply. Nothing was " +
    "shown or changed."
  );
}

const ROOM_REASONS = new Set(["group_chat", "unknown_chat"]);

/**
 * Why an owner command may not answer in the chat it came from:
 * - `group_chat` for a group or channel room, or a thread or topic in one: by its session key, as scans read a turn's
 *   chat, or by a reply address that names a room;
 * - `unknown_chat` for the agent's main session while OpenClaw routes rooms into it, from any surface (its transcript
 *   is the rooms' too), and for a chat on a chat channel whose kind nothing says (no session key);
 * null for a direct chat (a thread or topic in one included), OpenClaw's own surfaces (the Control UI, webchat, the
 * terminal) and a gateway client with the admin scope, outside those.
 */
export function roomOf(ctx: OwnerContext, hostConfig: unknown, admin: boolean): "group_chat" | "unknown_chat" | null {
  const channel = channelOf(ctx.channel);
  const kind = chatKindOfTurn(ctx.sessionKey, channel, hostConfig);
  const addressed = [ctx.to, ctx.from].some((v) => typeof v === "string" && GROUP_SEGMENT.test(v.trim()));
  if (kind === "group" || addressed) return "group_chat";
  if (mainSharedWithRooms(ctx.sessionKey, hostConfig)) return "unknown_chat";
  if (kind === "direct" || channel === "chat" || admin) return null;
  return "unknown_chat";
}

/** Write one `command` record to the traffic log. */
export function auditCommand(
  audit: OwnerAudit,
  ctx: OwnerContext,
  verb: string,
  outcome: "allowed" | "refused",
  basis: string[],
  reason?: string,
): void {
  audit.traffic.write({
    kind: "command",
    verb,
    outcome,
    basis,
    sender_ref: senderRef(ctx.senderId, audit.salt()),
    channel: typeof ctx.channel === "string" ? ctx.channel : null,
    ...(reason ? { reason } : {}),
  });
}

/**
 * Decide whether the sender may run this command in this chat and audit the decision. `hostConfig` is OpenClaw's
 * config as it is now: it says whether rooms share the agent's main session.
 */
export function ownerGate<C extends OwnerContext>(
  ctx: C,
  verb: string,
  audit: OwnerAudit,
  hostConfig: () => unknown = () => undefined,
): OwnerGate {
  const scopes = ctx.gatewayClientScopes;
  const admin = Array.isArray(scopes) && scopes.includes("operator.admin");
  const basis = admin ? ["operator.admin"] : ["sender_is_owner"];
  const record = (outcome: "allowed" | "refused", recordBasis: string[], reason?: string) =>
    auditCommand(audit, ctx, verb, outcome, recordBasis, reason);
  // The host's check is synchronous; anything else cannot vouch for this write, so it counts as stale.
  const current = (): boolean => {
    try {
      const result: unknown = ctx.assertOwnerCurrent?.();
      if (result && typeof (result as PromiseLike<unknown>).then === "function") {
        Promise.resolve(result).catch(() => undefined);
        return false;
      }
      return true;
    } catch {
      return false;
    }
  };

  const refused = (recordBasis: string[], reason: string): OwnerGate => {
    record("refused", recordBasis, reason);
    return {
      owner: false,
      basis: recordBasis,
      reason,
      beforeWrite: () => {
        throw new OwnerRefused(reason);
      },
    };
  };
  if (ctx.senderIsOwner !== true || typeof ctx.assertOwnerCurrent !== "function") {
    return refused(["none"], "not_owner");
  }
  if (!current()) return refused(basis, "stale_owner");
  const room = roomOf(ctx, hostConfig(), admin);
  if (room) return refused(basis, room);
  record("allowed", basis);
  return {
    owner: true,
    basis,
    beforeWrite: () => {
      if (!current()) {
        record("refused", basis, "stale_owner");
        throw new OwnerRefused("stale_owner");
      }
    },
  };
}

export interface OwnerCommandDef<C extends OwnerContext> {
  name: string;
  description: string;
  /** The verb in audit records and refusals; defaults to `name`. */
  verb?: string;
  handler: (ctx: C, gate: OwnerGate) => { text?: string } | Promise<{ text?: string }>;
}

/**
 * A command definition for `api.registerCommand` that runs `handler` only for the owner, and only outside a group or
 * channel room (see `ownerGate`).
 */
export function ownerCommand<C extends OwnerContext>(
  def: OwnerCommandDef<C>,
  audit: OwnerAudit,
  hostConfig: () => unknown = () => undefined,
) {
  const verb = def.verb ?? def.name;
  return {
    name: def.name,
    description: def.description,
    requiredScopes: [...OWNER_SCOPES],
    handler: async (ctx: C): Promise<{ text?: string }> => {
      let gate: OwnerGate;
      try {
        gate = ownerGate(ctx, verb, audit, hostConfig);
      } catch {
        try {
          auditCommand(audit, {}, verb, "refused", ["none"], "error");
        } catch {
          // nothing more to record
        }
        return { text: refusal(verb) };
      }
      if (!gate.owner) return { text: ROOM_REASONS.has(gate.reason ?? "") ? roomRefusal(verb) : refusal(verb) };
      try {
        return await def.handler(ctx, gate);
      } catch (err) {
        if (err instanceof OwnerRefused) return { text: refusal(verb) };
        throw err;
      }
    },
  };
}
