/**
 * Owner-only commands: who may run a command that changes how Sentrook behaves.
 *
 * OpenClaw tells a command handler whether the sender is the owner (`senderIsOwner`) and gives it
 * `assertOwnerCurrent`, which throws once that authority is gone, but only when the command declares
 * `requiredScopes`. Owner commands therefore require `operator.admin`: the owner's default Control UI
 * connection holds it, and limited Control UI sessions and write-only CLI clients are refused by the
 * host before the handler runs. Inside the handler the owner is `senderIsOwner === true` with
 * `assertOwnerCurrent` present and passing; the command calls `gate.beforeWrite()` before each write,
 * so an owner demoted mid-command writes nothing more.
 *
 * Anyone holding the shared gateway token has `operator.admin` and so counts as the owner. Control UI
 * connections carry no sender id, so their audit records show the basis, not a name.
 *
 * Warning for installers: an entry in `commands.ownerAllowFrom` that matches no one locks unlisted
 * non-admin clients out of every plugin command ("requires authorization"). The plugin cannot see the
 * sender roster, so it cannot check those entries for you.
 *
 * Every attempt, allowed or refused, is written to the traffic log as a `command` record. A sender
 * id, when there is one, is stored only as a salted hash.
 */

import { createHmac } from "node:crypto";

export const OWNER_SCOPES = ["operator.admin"];

/** The fields of OpenClaw's command context the owner check reads. */
export interface OwnerContext {
  senderId?: string;
  channel?: string;
  senderIsOwner?: unknown;
  assertOwnerCurrent?: () => void;
  gatewayClientScopes?: string[];
}

export interface OwnerAudit {
  traffic: { write: (record: Record<string, unknown>) => void };
  salt: () => string;
}

export interface OwnerGate {
  owner: boolean;
  basis: string[];
  /** Call before each write; throws `OwnerRefused` (and audits it) once the sender is no longer the owner. */
  beforeWrite: () => void;
}

export class OwnerRefused extends Error {}

export function senderRef(senderId: string | undefined, salt: string): string | null {
  return senderId ? `u_${createHmac("sha256", salt).update(senderId).digest("hex").slice(0, 16)}` : null;
}

export function refusal(verb: string): string {
  return `Only the owner can run /sentrook ${verb}: use the owner's Control UI connection (gateway scope operator.admin).`;
}

/** Decide whether the sender may run this command and audit the decision. */
export function ownerGate<C extends OwnerContext>(ctx: C, verb: string, audit: OwnerAudit): OwnerGate {
  const basis = ctx.gatewayClientScopes?.includes("operator.admin") ? ["operator.admin"] : ["sender_is_owner"];
  const record = (outcome: "allowed" | "refused", recordBasis: string[], reason?: string) =>
    audit.traffic.write({
      kind: "command",
      verb,
      outcome,
      basis: recordBasis,
      sender_ref: senderRef(ctx.senderId, audit.salt()),
      channel: ctx.channel ?? null,
      ...(reason ? { reason } : {}),
    });
  const current = (): boolean => {
    try {
      ctx.assertOwnerCurrent?.();
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
      beforeWrite: () => {
        throw new OwnerRefused(reason);
      },
    };
  };
  if (ctx.senderIsOwner !== true || typeof ctx.assertOwnerCurrent !== "function") {
    return refused(["none"], "not_owner");
  }
  if (!current()) return refused(basis, "stale_owner");
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

/** A command definition for `api.registerCommand` that runs `handler` only for the owner. */
export function ownerCommand<C extends OwnerContext>(def: OwnerCommandDef<C>, audit: OwnerAudit) {
  const verb = def.verb ?? def.name;
  return {
    name: def.name,
    description: def.description,
    requiredScopes: [...OWNER_SCOPES],
    handler: async (ctx: C): Promise<{ text?: string }> => {
      let gate: OwnerGate;
      try {
        gate = ownerGate(ctx, verb, audit);
      } catch {
        return { text: refusal(verb) };
      }
      if (!gate.owner) return { text: refusal(verb) };
      try {
        return await def.handler(ctx, gate);
      } catch (err) {
        if (err instanceof OwnerRefused) return { text: refusal(verb) };
        throw err;
      }
    },
  };
}
