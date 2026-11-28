/**
 * Whether OpenClaw's tool policy still hides the agent's setup tools (`sentrook_setup_report`,
 * `sentrook_propose_setup`) from the owner's turns.
 *
 * A tool profile (`tools.profile`) no longer hides them: the manifest lists both for every profile under
 * `toolMetadata.<tool>.profiles`. An explicit `allow` list that names neither the tool, the plugin (`sentrook`),
 * `group:plugins` nor a matching glob, or a `deny` list that names any of them, still does, globally (`tools`) or
 * for one agent (`agents.list[].tools`), and for one model provider (`byProvider.<provider>`). Entries match as
 * OpenClaw matches them: trimmed, lower case, `*` as a glob.
 */

import { TOOL as PROPOSE_TOOL } from "./proposals.ts";
import { TOOL as REPORT_TOOL } from "./setupReport.ts";

const PLUGIN_ID = "sentrook";
const SETUP_TOOLS = [REPORT_TOOL, PROPOSE_TOOL];

export interface HiddenTool {
  tool: string;
  /** The setting that hides it, e.g. `tools.deny` or `agents.list[main].tools.allow`. */
  where: string;
}

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function entries(v: unknown): string[] | null {
  if (!Array.isArray(v)) return null;
  return v.filter((e): e is string => typeof e === "string").map((e) => e.trim().toLowerCase()).filter(Boolean);
}

function matches(value: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (!pattern.includes("*")) return value === pattern;
  const re = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${re}$`).test(value);
}

/** Whether a policy list entry names this tool: the tool itself, the plugin, all plugin tools, or a glob of one. */
function names(list: string[], tool: string): boolean {
  return list.some((p) => matches(tool, p) || matches(PLUGIN_ID, p) || matches("group:plugins", p));
}

function policyHides(policy: unknown, prefix: string): HiddenTool[] {
  if (!isRecord(policy)) return [];
  const hidden: HiddenTool[] = [];
  // A provider's own lists (`byProvider.<provider>`) apply on top for turns on that model provider.
  if (isRecord(policy.byProvider)) {
    for (const [provider, sub] of Object.entries(policy.byProvider)) {
      hidden.push(...policyHides(sub, `${prefix}.byProvider.${provider}`));
    }
  }
  const deny = entries(policy.deny);
  const allow = entries(policy.allow);
  const also = entries(policy.alsoAllow) ?? [];
  for (const tool of SETUP_TOOLS) {
    if (deny && names(deny, tool)) hidden.push({ tool, where: `${prefix}.deny` });
    else if (allow && allow.length > 0 && !names(allow, tool) && !names(also, tool)) {
      hidden.push({ tool, where: `${prefix}.allow` });
    }
  }
  return hidden;
}

/** Each setup tool an allow or deny list in OpenClaw's config hides, with the setting; [] when none does. */
export function hiddenSetupTools(hostConfig: unknown): HiddenTool[] {
  if (!isRecord(hostConfig)) return [];
  const hidden = policyHides(hostConfig.tools, "tools");
  const agents = isRecord(hostConfig.agents) ? hostConfig.agents.list : undefined;
  if (Array.isArray(agents)) {
    agents.forEach((agent, i) => {
      if (!isRecord(agent)) return;
      const id = typeof agent.id === "string" && agent.id ? agent.id : String(i);
      hidden.push(...policyHides(agent.tools, `agents.list[${id}].tools`));
    });
  }
  return hidden;
}

/** The verify line when the setup tools are hidden (reported, not failed), or null when the agent can see them. */
export function setupToolsCheck(hostConfig: unknown): { name: string; ok: boolean; detail: string } | null {
  const hidden = hiddenSetupTools(hostConfig);
  if (hidden.length === 0) return null;
  const by = [...new Set(hidden.map((h) => h.where))]
    .map((where) => `${hidden.filter((h) => h.where === where).map((h) => h.tool).join(" and ")} by ${where}`)
    .join("; ");
  return {
    name: "setup tools",
    ok: true,
    detail:
      `warning: hidden from the agent, so it cannot help set Sentrook up (${by}). ` +
      `Add "${PLUGIN_ID}" to that allow list or take it out of that deny list; /sentrook-setup still works without them.`,
  };
}
