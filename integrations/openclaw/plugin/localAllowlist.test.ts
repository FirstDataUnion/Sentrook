import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";

import { buildPlanirSnapshot } from "./planir.ts";
import {
  extractMatchedRuleIds,
  isHighRiskCommand,
  isValidEntry,
  loadAllowlist,
  matchAllowlist,
  parseBindableScript,
  recordAllowAlways,
  resolveAllowlistConfig,
  resolveScriptPath,
  sha256Buffer,
  skeletonizeCommand,
  skeletonizeScriptArgs,
  tokenizeArgv,
  type AllowlistConfig,
} from "./localAllowlist.ts";

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

function tempAllowlist(): { dir: string; config: AllowlistConfig } {
  const dir = mkdtempSync(join(tmpdir(), "sentrook-allowlist-"));
  tempDirs.push(dir);
  return {
    dir,
    config: {
      enabled: true,
      path: join(dir, "sentrook-allowlist.json"),
      scriptBind: true,
    },
  };
}

function planForCommand(command: string, tool = "exec") {
  return buildPlanirSnapshot({
    runId: "sess:run_1",
    sessionId: "sess-1",
    intent: "test",
    intentKind: "user",
    executed: [],
    pending: { tool, args: { command } },
  });
}

function planForArgs(tool: string, args: Record<string, unknown>) {
  return buildPlanirSnapshot({
    runId: "sess:run_1",
    sessionId: "sess-1",
    intent: "test",
    intentKind: "user",
    executed: [],
    pending: { tool, args },
  });
}

function logWithRules(...ids: string[]): Record<string, unknown> {
  return { matched_rules: ids.map((id) => ({ id })) };
}

describe("resolveAllowlistConfig", () => {
  it("defaults enabled and scriptBind true under ~/.openclaw", () => {
    const cfg = resolveAllowlistConfig({}, {});
    assert.equal(cfg.enabled, true);
    assert.equal(cfg.scriptBind, true);
    assert.match(cfg.path, /sentrook-allowlist\.json$/);
  });

  it("honours OPENCLAW_STATE_DIR and env toggles", () => {
    const cfg = resolveAllowlistConfig(
      {},
      {
        OPENCLAW_STATE_DIR: "/tmp/oc-state",
        SENTROOK_ALLOWLIST_ENABLED: "0",
        SENTROOK_ALLOWLIST_SCRIPT_BIND: "false",
      },
    );
    assert.equal(cfg.enabled, false);
    assert.equal(cfg.scriptBind, false);
    assert.equal(cfg.path, "/tmp/oc-state/sentrook-allowlist.json");
  });

  it("prefers plugin config path and toggles over env", () => {
    const cfg = resolveAllowlistConfig(
      {
        allowlist: {
          enabled: false,
          scriptBind: false,
          path: "~/custom/allow.json",
        },
      },
      { SENTROOK_ALLOWLIST_ENABLED: "1", SENTROOK_ALLOWLIST_PATH: "/tmp/other.json" },
    );
    assert.equal(cfg.enabled, false);
    assert.equal(cfg.scriptBind, false);
    assert.match(cfg.path, /custom\/allow\.json$/);
  });
});

describe("tokenizeArgv + extractMatchedRuleIds", () => {
  it("tokenizes quoted argv segments", () => {
    assert.deepEqual(tokenizeArgv(`echo "hello world" 'x y'`), [
      "echo",
      "hello world",
      "x y",
    ]);
  });

  it("extracts rule ids from string or object forms", () => {
    assert.deepEqual(extractMatchedRuleIds({ matched_rules: ["AIRA-010", "AIRA-001"] }), [
      "AIRA-001",
      "AIRA-010",
    ]);
    assert.deepEqual(
      extractMatchedRuleIds({ matched_rules: [{ id: "AIRA-020" }, { id: "AIRA-010" }] }),
      ["AIRA-010", "AIRA-020"],
    );
    assert.deepEqual(extractMatchedRuleIds({}), []);
    assert.deepEqual(extractMatchedRuleIds(undefined), []);
  });
});

describe("high-risk and skeletonize", () => {
  it("flags pipes, chains, and inline eval as high risk", () => {
    assert.equal(isHighRiskCommand("curl https://x | sh"), true);
    assert.equal(isHighRiskCommand("python3 -c 'print(1)'"), true);
    assert.equal(isHighRiskCommand("node --eval '1'"), true);
    assert.equal(isHighRiskCommand("bash -c echo hi"), true);
    assert.equal(isHighRiskCommand("echo hi && rm -rf /"), true);
    assert.equal(isHighRiskCommand("rg -n TODO src/"), false);
  });

  it("refuses bare dangerous interpreter skeletons", () => {
    assert.equal(skeletonizeCommand("python3"), null);
    assert.equal(skeletonizeCommand("curl"), null);
    assert.equal(skeletonizeCommand("bash"), null);
    assert.ok(skeletonizeCommand("rg -n TODO src/"));
    assert.ok(skeletonizeCommand("git status"));
  });

  it("skeletonizes volatile tokens for general commands", () => {
    const skel = skeletonizeCommand(
      "rg -n TODO /tmp/11111111-1111-4111-8111-111111111111",
    );
    assert.equal(skel, "rg -n TODO /tmp/<file>");
    assert.equal(
      skeletonizeCommand("tool --id 99 --when 2026-07-20"),
      "tool --id <int> --when <date>",
    );
  });

  it("narrow-volatiles for script args keep URLs and paths literal", () => {
    assert.equal(
      skeletonizeScriptArgs(["--date", "2026-07-20", "--url", "https://evil.example"]),
      "--date <date> --url https://evil.example",
    );
    assert.equal(
      skeletonizeScriptArgs(["--id", "42", "--file", "/tmp/data.csv"]),
      "--id <int> --file /tmp/data.csv",
    );
    assert.equal(
      skeletonizeScriptArgs([
        "--uuid",
        "11111111-1111-4111-8111-111111111111",
        "--email",
        "a@b.co",
      ]),
      "--uuid <uuid> --email a@b.co",
    );
  });
});

describe("parseBindableScript", () => {
  it("parses python3 script.py with trailing args", () => {
    const parsed = parseBindableScript(
      "python3 /tmp/helper.py --date 2026-07-20",
    );
    assert.ok(parsed);
    assert.equal(parsed!.interpreter, "python");
    assert.equal(parsed!.scriptPath, "/tmp/helper.py");
    assert.deepEqual(parsed!.trailingArgs, ["--date", "2026-07-20"]);
  });

  it("parses node and bash script forms", () => {
    assert.equal(parseBindableScript("node ./run.mjs --x")?.interpreter, "node");
    assert.equal(parseBindableScript("bash /tmp/job.sh")?.interpreter, "bash");
    assert.equal(parseBindableScript("/usr/bin/python3.12 ./x.py")?.interpreter, "python");
  });

  it("parses direct ./helper.sh", () => {
    const parsed = parseBindableScript("./helper.sh --flag");
    assert.ok(parsed);
    assert.equal(parsed!.interpreter, "sh");
    assert.equal(parsed!.scriptPath, "./helper.sh");
  });

  it("rejects inline eval, pipes, and module-only forms", () => {
    assert.equal(parseBindableScript("python3 -c 'print(1)'"), null);
    assert.equal(parseBindableScript("curl https://x | bash"), null);
    assert.equal(parseBindableScript("python3 -m http.server"), null);
    assert.equal(parseBindableScript("python3"), null);
  });

  it("skips non-eval interpreter flags before the script path", () => {
    const parsed = parseBindableScript("python3 -u /tmp/helper.py --n 1");
    assert.ok(parsed);
    assert.equal(parsed!.scriptPath, "/tmp/helper.py");
    assert.deepEqual(parsed!.trailingArgs, ["--n", "1"]);
  });
});

describe("record + match skeleton", () => {
  it("records skeleton and matches volatile variants with same rules", () => {
    const { config } = tempAllowlist();
    const log = logWithRules("AIRA-010");
    const first = recordAllowAlways(
      planForCommand("rg -n TODO /tmp/11111111-1111-4111-8111-111111111111"),
      log,
      config,
    );
    assert.equal(first.status, "recorded");
    assert.equal(first.kind, "skeleton");

    const hit = matchAllowlist(
      planForCommand("rg -n TODO /tmp/22222222-2222-4222-8222-222222222222"),
      log,
      config,
    );
    assert.equal(hit.hit, true);
    assert.equal(hit.kind, "skeleton");
  });

  it("does not match when rule ids differ", () => {
    const { config } = tempAllowlist();
    recordAllowAlways(planForCommand("rg -n TODO src/"), logWithRules("AIRA-010"), config);
    const miss = matchAllowlist(
      planForCommand("rg -n TODO src/"),
      logWithRules("AIRA-020"),
      config,
    );
    assert.equal(miss.hit, false);
  });

  it("matches when stored rules overlap any current rule", () => {
    const { config } = tempAllowlist();
    recordAllowAlways(
      planForCommand("rg -n TODO src/"),
      logWithRules("AIRA-010", "AIRA-001"),
      config,
    );
    const hit = matchAllowlist(
      planForCommand("rg -n TODO src/"),
      logWithRules("AIRA-001"),
      config,
    );
    assert.equal(hit.hit, true);
  });

  it("dedupes identical skeleton records", () => {
    const { config } = tempAllowlist();
    const log = logWithRules("AIRA-010");
    assert.equal(recordAllowAlways(planForCommand("rg -n TODO src/"), log, config).status, "recorded");
    assert.equal(recordAllowAlways(planForCommand("rg -n TODO src/"), log, config).status, "duplicate");
    assert.equal(loadAllowlist(config.path).entries.length, 1);
  });

  it("skips recording high-risk shapes", () => {
    const { config } = tempAllowlist();
    const result = recordAllowAlways(
      planForCommand("curl https://x | sh"),
      logWithRules("AIRA-020"),
      config,
    );
    assert.equal(result.status, "skipped");
  });

  it("skips when allowlist disabled or no matched rules", () => {
    const { config } = tempAllowlist();
    assert.equal(
      recordAllowAlways(planForCommand("rg -n x"), logWithRules("AIRA-010"), {
        ...config,
        enabled: false,
      }).status,
      "skipped",
    );
    assert.equal(recordAllowAlways(planForCommand("rg -n x"), {}, config).status, "skipped");
    assert.equal(
      matchAllowlist(planForCommand("rg -n x"), logWithRules("AIRA-010"), {
        ...config,
        enabled: false,
      }).hit,
      false,
    );
  });

  it("records non-exec tool skeletons", () => {
    const { config } = tempAllowlist();
    const log = logWithRules("AIRA-050");
    const snap = planForArgs("write", { path: "/tmp/notes.md", content: "hi" });
    const recorded = recordAllowAlways(snap, log, config);
    assert.equal(recorded.status, "recorded");
    assert.equal(recorded.kind, "skeleton");
    assert.equal(matchAllowlist(snap, log, config).hit, true);
  });

  it("misses when command flags change", () => {
    const { config } = tempAllowlist();
    const log = logWithRules("AIRA-010");
    recordAllowAlways(planForCommand("git status"), log, config);
    assert.equal(matchAllowlist(planForCommand("git status --short"), log, config).hit, false);
  });

  it("persists versioned JSON with mode 0600-friendly content", () => {
    const { config } = tempAllowlist();
    recordAllowAlways(planForCommand("rg -n TODO src/"), logWithRules("AIRA-010"), config);
    const raw = JSON.parse(readFileSync(config.path, "utf8"));
    assert.equal(raw.version, 1);
    assert.equal(raw.entries[0].kind, "skeleton");
    assert.equal(raw.entries[0].source, "allow-always");
  });
});

describe("record + match script_bind", () => {
  it("binds script content hash and matches date/int/uuid arg variants", () => {
    const { dir, config } = tempAllowlist();
    const scriptPath = join(dir, "helper.py");
    writeFileSync(scriptPath, "print('hello')\n", "utf8");

    const log = logWithRules("AIRA-010");
    const recorded = recordAllowAlways(
      planForCommand(
        `python3 ${scriptPath} --date 2026-07-17 --count 3 --id 11111111-1111-4111-8111-111111111111`,
      ),
      log,
      config,
      { cwd: dir },
    );
    assert.equal(recorded.status, "recorded");
    assert.equal(recorded.kind, "script_bind");

    const hit = matchAllowlist(
      planForCommand(
        `python3 ${scriptPath} --date 2026-07-20 --count 9 --id 22222222-2222-4222-8222-222222222222`,
      ),
      log,
      config,
      { cwd: dir },
    );
    assert.equal(hit.hit, true);
    assert.equal(hit.kind, "script_bind");
  });

  it("misses when URL trailing arg changes", () => {
    const { dir, config } = tempAllowlist();
    const scriptPath = join(dir, "helper.py");
    writeFileSync(scriptPath, "print('hello')\n", "utf8");
    const log = logWithRules("AIRA-010");

    recordAllowAlways(
      planForCommand(`python3 ${scriptPath} --url https://safe.example`),
      log,
      config,
      { cwd: dir },
    );
    const miss = matchAllowlist(
      planForCommand(`python3 ${scriptPath} --url https://evil.example`),
      log,
      config,
      { cwd: dir },
    );
    assert.equal(miss.hit, false);
  });

  it("misses when path trailing arg changes", () => {
    const { dir, config } = tempAllowlist();
    const scriptPath = join(dir, "helper.py");
    writeFileSync(scriptPath, "print('hello')\n", "utf8");
    const log = logWithRules("AIRA-010");
    recordAllowAlways(
      planForCommand(`python3 ${scriptPath} --out /tmp/a.csv`),
      log,
      config,
      { cwd: dir },
    );
    assert.equal(
      matchAllowlist(
        planForCommand(`python3 ${scriptPath} --out /tmp/b.csv`),
        log,
        config,
        { cwd: dir },
      ).hit,
      false,
    );
  });

  it("misses when script content changes", () => {
    const { dir, config } = tempAllowlist();
    const scriptPath = join(dir, "helper.py");
    writeFileSync(scriptPath, "print('v1')\n", "utf8");
    const log = logWithRules("AIRA-010");

    recordAllowAlways(
      planForCommand(`python3 ${scriptPath}`),
      log,
      config,
      { cwd: dir },
    );
    writeFileSync(scriptPath, "print('v2')\n", "utf8");
    const miss = matchAllowlist(
      planForCommand(`python3 ${scriptPath}`),
      log,
      config,
      { cwd: dir },
    );
    assert.equal(miss.hit, false);
  });

  it("misses when script path differs even if content matches", () => {
    const { dir, config } = tempAllowlist();
    const a = join(dir, "a.py");
    const b = join(dir, "b.py");
    writeFileSync(a, "print('same')\n", "utf8");
    writeFileSync(b, "print('same')\n", "utf8");
    const log = logWithRules("AIRA-010");
    recordAllowAlways(planForCommand(`python3 ${a}`), log, config, { cwd: dir });
    assert.equal(matchAllowlist(planForCommand(`python3 ${b}`), log, config, { cwd: dir }).hit, false);
  });

  it("does not fall back to skeleton for bindable script forms", () => {
    const { dir, config } = tempAllowlist();
    const scriptPath = join(dir, "helper.py");
    writeFileSync(scriptPath, "print('hello')\n", "utf8");
    const log = logWithRules("AIRA-010");
    const skeletonOnly: AllowlistConfig = { ...config, scriptBind: false };
    const recorded = recordAllowAlways(
      planForCommand(`python3 ${scriptPath} --date 2026-07-17`),
      log,
      skeletonOnly,
      { cwd: dir },
    );
    assert.ok(recorded.status === "recorded" || recorded.status === "skipped");

    const miss = matchAllowlist(
      planForCommand(`python3 ${scriptPath} --date 2026-07-20`),
      log,
      { ...config, scriptBind: true },
      { cwd: dir },
    );
    assert.equal(miss.hit, false);
  });

  it("skips record when script file is unreadable", () => {
    const { config } = tempAllowlist();
    const result = recordAllowAlways(
      planForCommand("python3 /nonexistent/nope-sentrook-helper.py"),
      logWithRules("AIRA-010"),
      config,
      {
        readFile: () => null,
      },
    );
    assert.equal(result.status, "skipped");
    assert.match(result.reason ?? "", /unreadable/);
  });

  it("never records python -c as script_bind or skeleton", () => {
    const { config } = tempAllowlist();
    const result = recordAllowAlways(
      planForCommand("python3 -c 'print(1)'"),
      logWithRules("AIRA-010"),
      config,
    );
    assert.equal(result.status, "skipped");
    assert.equal(loadAllowlist(config.path).entries.length, 0);
  });

  it("dedupes identical script_bind records", () => {
    const { dir, config } = tempAllowlist();
    const scriptPath = join(dir, "helper.py");
    writeFileSync(scriptPath, "print(1)\n", "utf8");
    const log = logWithRules("AIRA-010");
    const cmd = `python3 ${scriptPath} --n 1`;
    assert.equal(recordAllowAlways(planForCommand(cmd), log, config, { cwd: dir }).status, "recorded");
    assert.equal(recordAllowAlways(planForCommand(cmd), log, config, { cwd: dir }).status, "duplicate");
    assert.equal(loadAllowlist(config.path).entries.length, 1);
  });

  it("resolves relative script paths against cwd", () => {
    const { dir } = tempAllowlist();
    writeFileSync(join(dir, "rel.py"), "x\n", "utf8");
    assert.equal(resolveScriptPath("./rel.py", dir), join(dir, "rel.py"));
  });

  it("sha256 is stable for identical bytes", () => {
    const a = sha256Buffer(Buffer.from("abc"));
    const b = sha256Buffer(Buffer.from("abc"));
    assert.equal(a, b);
    assert.notEqual(a, sha256Buffer(Buffer.from("abd")));
  });

  it("tolerates corrupt allowlist files by treating them as empty", () => {
    const { config } = tempAllowlist();
    writeFileSync(config.path, "{not-json", "utf8");
    assert.deepEqual(loadAllowlist(config.path), { version: 1, entries: [] });
  });

  it("rejects poisoned entries with wrong source, future created_at, or bad metadata", () => {
    const { config } = tempAllowlist();
    const now = Date.now();
    const validSkeleton = {
      kind: "skeleton",
      tool: "exec",
      matched_rule_ids: ["AIRA-010"],
      skeleton: "rg -n TODO src/",
      created_at: new Date(now - 60_000).toISOString(),
      source: "allow-always",
    };
    assert.equal(isValidEntry(validSkeleton, now), true);

    assert.equal(isValidEntry({ ...validSkeleton, source: "manual" }, now), false);
    assert.equal(
      isValidEntry(
        { ...validSkeleton, created_at: new Date(now + 120_000).toISOString() },
        now,
      ),
      false,
    );
    assert.equal(isValidEntry({ ...validSkeleton, matched_rule_ids: [] }, now), false);

    writeFileSync(
      config.path,
      JSON.stringify({
        version: 1,
        entries: [
          validSkeleton,
          { ...validSkeleton, source: "manual" },
          {
            kind: "script_bind",
            tool: "exec",
            interpreter: "python",
            script_path: "/tmp/x.py",
            content_sha256: "not-a-hash",
            args_skeleton: "",
            matched_rule_ids: ["AIRA-010"],
            created_at: validSkeleton.created_at,
            source: "allow-always",
          },
        ],
      }),
      "utf8",
    );
    assert.equal(loadAllowlist(config.path, { nowMs: now }).entries.length, 1);
  });

  it("does not match hand-edited entries missing allow-always metadata", () => {
    const { config } = tempAllowlist();
    writeFileSync(
      config.path,
      JSON.stringify({
        version: 1,
        entries: [
          {
            kind: "skeleton",
            tool: "exec",
            matched_rule_ids: ["AIRA-010"],
            skeleton: "rg -n TODO src/",
            created_at: new Date().toISOString(),
            source: "manual-edit",
          },
        ],
      }),
      "utf8",
    );
    const snap = planForCommand("rg -n TODO src/");
    const match = matchAllowlist(snap, logWithRules("AIRA-010"), config);
    assert.equal(match.hit, false);
  });
});
