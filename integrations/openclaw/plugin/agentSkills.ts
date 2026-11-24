/**
 * The agent skills and the always-loaded agent rules the plugin ships.
 *
 * Two skills, `sentrook-guide` (how Sentrook works, for explaining it) and `sentrook-setup` (helping the owner set it
 * up), are folders under `skills/`, which `openclaw.plugin.json` lists: OpenClaw loads them while the plugin is
 * enabled, at the lowest precedence, and the agent reads one with a plain `read` of its `SKILL.md`. The rules the agent
 * must follow whether or not it opens a skill (never run the commands that change Sentrook, never edit its settings or
 * folder, never retry a blocked call reworded) are in `agent-rules.txt` and go into the system prompt as the
 * `/sentrook` command's prompt guidance. All three files are rendered for OpenClaw from the shared templates in
 * `integrations/skills/`.
 *
 * A skill is instructions by design, so reading one would otherwise look to the scanner like content trying to steer
 * the agent. A read whose resolved real path is one of the plugin's own shipped `SKILL.md` files is reported under
 * `SKILL_READ_TOOL`, which the scanner counts as a read of the agent's own skills. Anything else that holds the same
 * text (a copy in the workspace, a symlink swapped in for the plugin's file) is an ordinary `read`.
 *
 * Workspace, project, personal and managed skills outrank plugin skills, so a same-named skill there replaces ours
 * without any change to the plugin; `verify` names any it finds (`shadowCheck`).
 */

import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { openclawDir } from "./config.ts";

export const SKILL_NAMES = ["sentrook-guide", "sentrook-setup"] as const;

/**
 * The tool name a read of a shipped skill file is reported under. Tool names hold no `:`, so no tool the agent can
 * call has this name; a host tool that somehow does is reported as `SKILL_READ_TOOL_TAKEN`.
 */
export const SKILL_READ_TOOL = "plugin_skill:read";
export const SKILL_READ_TOOL_TAKEN = `${SKILL_READ_TOOL}#tool`;

/** The plugin's folder: next to index.ts when run from source, one level up from dist/index.js when bundled. */
export function pluginRoot(from: string = fileURLToPath(import.meta.url)): string | null {
  const here = path.dirname(from);
  for (const dir of [here, path.dirname(here)]) {
    if (existsSync(path.join(dir, "openclaw.plugin.json"))) return dir;
  }
  return null;
}

/** The rules, one per line, for OpenClaw's prompt guidance; empty when the file cannot be read. */
export function agentRules(root: string | null = pluginRoot()): string[] {
  if (!root) return [];
  try {
    return readFileSync(path.join(root, "agent-rules.txt"), "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

/** The path a `read` call names, as the host resolves it: `~` is the home folder, a relative path the workspace. */
function resolveReadPath(params: unknown, workspaceDir: unknown, home: string): string | null {
  const p = params as Record<string, unknown> | null | undefined;
  const raw = [p?.path, p?.file_path, p?.filePath].find((v) => typeof v === "string" && v.trim());
  if (typeof raw !== "string") return null;
  const given = raw.trim();
  if (given === "~" || given.startsWith("~/")) return path.join(home, given.slice(1));
  if (path.isAbsolute(given)) return given;
  return typeof workspaceDir === "string" && workspaceDir ? path.resolve(workspaceDir, given) : null;
}

/**
 * Whether a `read` with these parameters read one of the plugin's own shipped skill files: its resolved real path is
 * exactly `<plugin root>/skills/<name>/SKILL.md` (the root itself resolved), and that is a regular file. A copy, or a
 * symlink anywhere on the way that leads out of the plugin's folder, is not.
 */
export function isShippedSkillRead(
  params: unknown,
  opts: { workspaceDir?: unknown; home?: string; root?: string | null } = {},
): boolean {
  const root = opts.root === undefined ? pluginRoot() : opts.root;
  if (!root) return false;
  const target = resolveReadPath(params, opts.workspaceDir, opts.home ?? homedir());
  if (!target) return false;
  try {
    const real = realpathSync(target);
    const rootReal = realpathSync(root);
    return SKILL_NAMES.some((name) => {
      const shipped = path.join(rootReal, "skills", name, "SKILL.md");
      if (real !== shipped) return false;
      const st = lstatSync(shipped);
      return st.isFile() && !st.isSymbolicLink();
    });
  } catch {
    return false;
  }
}

/** The tool name to report for a host tool call that ran: `read` of a shipped skill file becomes `SKILL_READ_TOOL`. */
export function reportedTool(
  tool: string,
  params: unknown,
  opts: { workspaceDir?: unknown; home?: string; root?: string | null } = {},
): string {
  if (tool === SKILL_READ_TOOL) return SKILL_READ_TOOL_TAKEN;
  if (tool === "read" && isShippedSkillRead(params, opts)) return SKILL_READ_TOOL;
  return tool;
}

const expandHome = (p: string, home: string) => (p === "~" || p.startsWith("~/") ? path.join(home, p.slice(1)) : p);

const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v.trim() : null);

/**
 * The skill folders that outrank the plugin's own: each agent workspace's `skills/` and `.agents/skills/`, the
 * agents' Skill Workshop folders, OpenClaw's managed `skills/`, the personal `~/.agents/skills/` and any extra folders
 * in `skills.load.extraDirs`.
 */
export function outrankingSkillDirs(hostConfig: any, env: NodeJS.ProcessEnv, home: string = homedir()): string[] {
  const oc = openclawDir(env);
  const agents: any[] = Array.isArray(hostConfig?.agents?.list) ? hostConfig.agents.list : [];
  const defaultWs = str(hostConfig?.agents?.defaults?.workspace);
  const workspaces = new Set<string>([path.join(oc, "workspace")]);
  if (defaultWs) workspaces.add(expandHome(defaultWs, home));
  const agentDirs = new Set<string>();
  for (const a of agents) {
    const id = str(a?.id);
    const ws = str(a?.workspace);
    if (ws) workspaces.add(expandHome(ws, home));
    if (id) {
      workspaces.add(path.join(oc, `workspace-${id}`));
      if (defaultWs) workspaces.add(path.join(expandHome(defaultWs, home), id));
      agentDirs.add(path.join(oc, "agents", id, "agent"));
    }
    const dir = str(a?.agentDir);
    if (dir) agentDirs.add(expandHome(dir, home));
  }
  try {
    for (const id of readdirSync(path.join(oc, "agents"))) agentDirs.add(path.join(oc, "agents", id, "agent"));
  } catch {
    // No agents folder yet.
  }
  const extra: unknown[] = Array.isArray(hostConfig?.skills?.load?.extraDirs) ? hostConfig.skills.load.extraDirs : [];
  return [
    ...[...workspaces].flatMap((ws) => [path.join(ws, "skills"), path.join(ws, ".agents", "skills")]),
    ...[...agentDirs].map((d) => path.join(d, "workshop-skills")),
    path.join(oc, "skills"),
    path.join(home, ".agents", "skills"),
    ...extra.map(str).filter((d): d is string => d !== null).map((d) => expandHome(d, home)),
  ];
}

/** The `name:` in a SKILL.md's front matter; null when there is none. */
function frontmatterName(file: string): string | null {
  const lines = readFileSync(file, "utf8").slice(0, 4096).split("\n");
  if (lines[0]?.trim() !== "---") return null;
  for (const line of lines.slice(1)) {
    if (line.trim() === "---") return null;
    const m = /^name:\s*["']?([^"'\s]+)["']?\s*$/.exec(line.trim());
    if (m) return m[1]!;
  }
  return null;
}

/** At most this many skill folders are looked at in each folder. */
const MAX_CHILDREN = 500;

/**
 * Skills outside the plugin with the name of one of ours, which OpenClaw would load in place of ours: a folder named
 * like ours, or any skill whose front matter names it. Each as `<name> at <path>`.
 */
export function shadowingSkills(
  hostConfig: any,
  env: NodeJS.ProcessEnv,
  opts: { home?: string; root?: string | null } = {},
): string[] {
  const home = opts.home ?? homedir();
  const root = opts.root === undefined ? pluginRoot() : opts.root;
  let rootReal: string | null = null;
  try {
    rootReal = root ? realpathSync(root) : null;
  } catch {
    rootReal = null;
  }
  const ours = new Set<string>(SKILL_NAMES);
  const found = new Map<string, string>();
  for (const dir of new Set(outrankingSkillDirs(hostConfig, env, home))) {
    let children: string[];
    try {
      children = readdirSync(dir).slice(0, MAX_CHILDREN);
    } catch {
      continue;
    }
    for (const child of children) {
      const file = path.join(dir, child, "SKILL.md");
      try {
        const real = realpathSync(file);
        if (rootReal && real.startsWith(rootReal + path.sep)) continue; // our own files, linked in
        const name = ours.has(child) ? child : frontmatterName(file);
        if (name && ours.has(name)) found.set(file, `${name} at ${file}`);
      } catch {
        // No SKILL.md there, or unreadable.
      }
    }
  }
  return [...found.values()];
}

/** `verify`'s line about the plugin's skills: reported, not failed, like the other notes on settings. */
export function shadowCheck(hostConfig: any, env: NodeJS.ProcessEnv, opts: { home?: string; root?: string | null } = {}) {
  const found = shadowingSkills(hostConfig, env, opts);
  return {
    name: "agent skills",
    ok: true,
    detail: found.length
      ? `warning: another skill has the name of one the plugin ships and OpenClaw loads it instead: ${found.join("; ")}. ` +
        "Remove or rename it unless you wrote it yourself."
      : `${SKILL_NAMES.join(" and ")} from the plugin; no other skill of the same name`,
  };
}
