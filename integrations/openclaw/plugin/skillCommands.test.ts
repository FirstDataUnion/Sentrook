/**
 * The setup skill's fallback commands (for when the setup tools are missing) are ones the plugin accepts: each grant
 * parses with the grant command's own parser, each binding is set by the bind command, each trust reference parses
 * and is left unconfirmed so the owner reads the trust warning first.
 */
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { CMD } from "./commands.ts";
import { resolveConfig } from "./config.ts";
import * as grants from "./grants.ts";
import { parseRef } from "./trust.ts";

const SKILL = readFileSync(path.join(import.meta.dirname, "skills", "sentrook-setup", "SKILL.md"), "utf8");

/** The commands in the fallback table, as typed in chat. */
function fallbackCommands(): string[] {
  const section = SKILL.split("### If the setup tools are missing")[1]!.split("###")[0]!;
  return [...section.matchAll(/^\| [^|]+ \| `(\/sentrook-[^`]+)` \|$/gm)].map((m) => m[1]!);
}

test("the fallback table names the commands the plugin accepts", () => {
  const commands = fallbackCommands();
  assert.equal(commands.length, 8);
  const dir = mkdtempSync(path.join(tmpdir(), "skill-commands-"));
  const cfg = resolveConfig({ stateDir: dir }, { HOME: dir, OPENCLAW_STATE_DIR: dir });
  for (const line of commands) {
    const [typed, ...words] = line.split(" ");
    const rest = words.join(" ");
    if (typed === CMD("grant")) {
      const parsed = grants.parseGrant(rest, CMD);
      assert.equal(typeof parsed, "object", `${line}: ${String(parsed)}`);
    } else if (typed === CMD("bind")) {
      const { change, reply } = grants.bind(dir, cfg, rest, { basis: ["test"] }, new Date(), CMD, () => {});
      assert.ok(change, `${line}: ${reply}`);
    } else if (typed === CMD("trust-chat") || typed === CMD("trust-user")) {
      // no --confirm: the command's first reply says what trusting means and gives the confirm form
      assert.equal(words[0], "add", line);
      assert.ok(parseRef(words[1]), line);
      assert.equal(words.length, 2, line);
    } else {
      assert.fail(`unexpected command ${line}`);
    }
  }
});
