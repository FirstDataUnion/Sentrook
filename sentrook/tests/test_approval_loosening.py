"""Loosening the host's approval or allowlist settings takes the `guardrail_tampering` floor.

An agent that turns approvals off, sets the approval fallback to allow, enables YOLO, or puts a
wildcard in an allowlist removes the human from the loop for every later call, so such a change is
blocked whatever route it takes: the host's config command, its approvals commands, a direct write,
edit or patch of the config or approvals file, or a shell redirect into it. Tightening, unrelated
keys, reads, `@file` values and a narrow allowlist entry (one named command) do not take the floor; a
patch or batch file the call does not show gets the review tier.

Paths, hosts and file names are invented.
"""

from __future__ import annotations

import pytest
from test_aira_detectors import SELF, ex, floor_reasons, of, planir, run

from sentrook.converge.registry import REASONS
from sentrook.enums import Enforce

REASON = "guardrail.approval_loosening"
REVIEW_REASON = "guardrail.approval_loosening_review"


def fires(raw: dict) -> None:
    _, env = run(raw)
    floors = [f for f in env.floors if f.reason == REASON]
    assert len(floors) == 1, (floor_reasons(env), env.evidence["findings"])
    f = floors[0]
    assert f.floor == "guardrail_tampering" and f.min_risk == 1.0 and f.enforce is Enforce.BLOCK
    assert of(env, SELF, REASON)[0].value == 1.0


def reviews(raw: dict) -> None:
    """The review tier: the owner is always asked, the floor never blocks on its own."""
    _, env = run(raw)
    assert REASON not in floor_reasons(env), env.evidence["findings"]
    floors = [f for f in env.floors if f.reason == REVIEW_REASON]
    assert len(floors) == 1, (floor_reasons(env), env.evidence["findings"])
    f = floors[0]
    assert f.floor == "guardrail_tampering" and f.enforce is Enforce.REVIEW and f.min_risk < 0.8
    assert of(env, SELF, REVIEW_REASON) == []


def stays_silent(raw: dict) -> None:
    _, env = run(raw)
    assert REASON not in floor_reasons(env), env.evidence["findings"]
    assert env.floors == [] or all(f.floor != "guardrail_tampering" for f in env.floors), env.floors


def oc_edit(path: str, old: str, new: str, tool: str = "edit") -> dict:
    return planir(tool, "file_edit", {"path": path, "edits": [{"oldText": old, "newText": new}]})


def oc_write(path: str, content: str) -> dict:
    return planir("write", "file_write", {"path": path, "content": content})


def h_patch(path: str, old: str, new: str) -> dict:
    return planir(
        "patch",
        "file_edit",
        {"path": path, "old_string": old, "new_string": new},
        platform="hermes",
    )


def h_write(path: str, content: str) -> dict:
    return planir("write_file", "file_write", {"path": path, "content": content}, platform="hermes")


def h_ex(command: str) -> dict:
    return ex(command, platform="hermes")


APPROVALS = "~/.openclaw/exec-approvals.json"
OC_CONFIG = "~/.openclaw/openclaw.json"
H_CONFIG = "~/.hermes/config.yaml"


def test_reason_has_owner_text():
    assert REASON in REASONS and REVIEW_REASON in REASONS


def test_printf_text_is_read_with_its_escapes():
    fires(ex("printf 'approvals:\\n  mode: off\\n' >> ~/.hermes/config.yaml"))


# --------------------------------------------------------------------------- must fire


@pytest.mark.parametrize(
    "command",
    [
        "openclaw config set tools.exec.mode full",
        "openclaw config set tools.exec.security full",
        "openclaw config set tools.exec.ask off",
        "openclaw config set 'agents.entries.main.tools.exec.mode' full",
        "openclaw --profile work config set tools.exec.mode full",
        "npx -y openclaw@latest config set tools.exec.mode full",
        'openclaw config set tools.exec \'{"mode": "full"}\' --strict-json --merge',
        "openclaw config set tools.exec.askFallback full",
        "openclaw config set tools.exec.allowlist '[\"*\"]' --strict-json",
        'openclaw config set --batch-json \'[{"path": "tools.exec.mode", "value": "full"}]\'',
        "openclaw config patch --stdin <<'EOF'\n{ tools: { exec: { mode: \"full\" } } }\nEOF",
        "openclaw exec-policy preset yolo",
        "openclaw exec-policy set --ask-fallback full",
        "openclaw exec-policy set --security full --ask off",
        "openclaw exec-policy set --ask=off",
        'openclaw approvals allowlist add "*"',
        'openclaw approvals allowlist add --agent main "**"',
        'openclaw approvals allowlist add --agent "*" "/bin/bash"',
        "openclaw approvals set --stdin <<'EOF'\n"
        '{ version: 1, defaults: { security: "full", ask: "off", askFallback: "full" } }\nEOF',
        "cd /tmp && openclaw config set tools.exec.mode full",
        "bash -lc 'openclaw config set tools.exec.ask off'",
    ],
)
def test_openclaw_commands_fire(command):
    fires(ex(command))


@pytest.mark.parametrize(
    "command",
    [
        "hermes config set approvals.mode off",
        "hermes config set approvals.mode 'off'",
        "hermes config set approvals.cron_mode approve",
        "hermes config set approvals.single_query_mode approve",
        "hermes config set approvals.unattended_mode approve",
        "hermes config set HERMES_YOLO_MODE 1",
        "hermes config set command_allowlist '[\"*\"]'",
        "hermes --profile work config set approvals.mode off",
        "uv run hermes config set approvals.mode off",
        "python -m hermes_cli.main config set approvals.mode off",
        'hermes chat --yolo -q "tidy the repo"',
        'hermes --yolo chat -q "tidy the repo"',
        'HERMES_YOLO_MODE=1 hermes chat -q "tidy the repo"',
        "export HERMES_YOLO_MODE=true",
        "env HERMES_YOLO_MODE=1 hermes gateway run",
    ],
)
def test_hermes_commands_fire(command):
    fires(h_ex(command))


@pytest.mark.parametrize(
    "raw",
    [
        # OpenClaw approvals file: each loosening field, by edit.
        oc_edit(APPROVALS, '"askFallback": "deny"', '"askFallback": "full"'),
        oc_edit(APPROVALS, '"ask": "always"\n', '"ask": "off"\n'),
        oc_edit(APPROVALS, '"ask": "on-miss"', '"ask": "off"'),
        oc_edit(APPROVALS, '"security": "allowlist"', '"security": "full"'),
        oc_edit(APPROVALS, '"allowlist": []', '"allowlist": [{"pattern": "*"}]'),
        oc_edit(
            APPROVALS,
            '"allowlist": [\n        {"pattern": "~/bin/rg"}\n      ]',
            '"allowlist": [\n        {"pattern": "~/bin/rg"},\n        {"pattern": "**"}\n      ]',
        ),
        # By write.
        oc_write(
            APPROVALS,
            '{"version": 1, "defaults": {"security": "full", "ask": "off", "askFallback": "full"}}',
        ),
        # OpenClaw config: exec mode, legacy security/ask, approvals off, per-agent override.
        oc_edit(OC_CONFIG, '"mode": "allowlist"', '"mode": "full"'),
        oc_edit(
            OC_CONFIG,
            '"exec": {\n      "security": "allowlist",\n      "ask": "on-miss"',
            '"exec": {\n      "security": "full",\n      "ask": "off"',
        ),
        oc_edit(
            OC_CONFIG,
            '"mode": "allowlist",\n      "approvals": "on",',
            '"mode": "full",\n      "approvals": "off",',
        ),
        # Approval fallback and allowlist keys in any config file.
        oc_edit(APPROVALS, '"main": {"askFallback": "deny"}', '"main": {"askFallback": "allow"}'),
        oc_edit("~/.openclaw/exec-policy.json", '"allowlist": []\n', '"allowlist": ["*"]\n'),
        oc_edit(
            "~/.openclaw/extensions/gate/index.ts",
            'timeoutBehavior: "deny",',
            'timeoutBehavior: "allow",',
        ),
        # The patch tool.
        planir(
            "apply_patch",
            "file_edit",
            {
                "input": "*** Begin Patch\n*** Update File: /home/me/.openclaw/openclaw.json\n@@\n"
                '-      "mode": "allowlist",\n+      "mode": "full",\n*** End Patch'
            },
        ),
        planir(
            "apply_patch",
            "file_edit",
            {
                "input": "*** Begin Patch\n*** Update File: ~/.openclaw/exec-approvals.json\n@@\n"
                '-    "askFallback": "deny",\n+    "askFallback": "full",\n*** End Patch'
            },
        ),
    ],
    ids=[
        "approvals askFallback full",
        "approvals ask always to off",
        "approvals ask on-miss to off",
        "approvals security full",
        "approvals wildcard entry",
        "approvals wildcard entry appended",
        "approvals write",
        "config exec mode full",
        "config legacy security and ask",
        "config approvals off",
        "agent askFallback allow",
        "allowlist star",
        "timeoutBehavior allow",
        "apply_patch config",
        "apply_patch approvals",
    ],
)
def test_openclaw_file_changes_fire(raw):
    fires(raw)


@pytest.mark.parametrize(
    "raw",
    [
        h_patch(H_CONFIG, "approvals:\n  mode: smart", "approvals:\n  mode: off"),
        h_patch(H_CONFIG, "  mode: manual\n", "  mode: 'off'\n"),
        h_patch(H_CONFIG, "  cron_mode: deny", "  cron_mode: approve"),
        h_patch(H_CONFIG, "  unattended_mode: deny", "  unattended_mode: approve"),
        h_patch(H_CONFIG, "command_allowlist: []", 'command_allowlist: ["*"]'),
        h_patch(
            H_CONFIG,
            "command_allowlist:\n- git status\n",
            "command_allowlist:\n- git status\n- '*'\n",
        ),
        h_patch("~/.hermes/profiles/work/config.yaml", "  mode: smart", "  mode: off"),
        h_write(H_CONFIG, "model:\n  default: m\napprovals:\n  mode: off\n  timeout: 300\n"),
        h_write("~/.hermes/.env", "OPENROUTER_API_KEY=x\nHERMES_YOLO_MODE=1\n"),
        planir(
            "patch",
            "file_edit",
            {
                "mode": "patch",
                "patch": "*** Begin Patch\n*** Update File: ~/.hermes/config.yaml\n@@\n"
                " approvals:\n-  mode: smart\n+  mode: off\n*** End Patch",
            },
            platform="hermes",
        ),
    ],
    ids=[
        "patch mode off",
        "patch manual to off",
        "patch cron approve",
        "patch unattended approve",
        "patch allowlist star",
        "patch allowlist star appended",
        "profile config",
        "write config",
        "write env yolo",
        "v4a patch",
    ],
)
def test_hermes_file_changes_fire(raw):
    fires(raw)


@pytest.mark.parametrize(
    "command",
    [
        "echo 'HERMES_YOLO_MODE=1' >> ~/.hermes/.env",
        "echo 'HERMES_YOLO_MODE=1' | tee -a ~/.hermes/.env",
        "sed -i 's/mode: smart/mode: off/' ~/.hermes/config.yaml",
        "cat > ~/.openclaw/exec-approvals.json <<'EOF'\n"
        '{"version": 1, "defaults": {"security": "full", "ask": "off", "askFallback": "full"}}\n'
        "EOF",
        'sed -i \'s/"askFallback": "deny"/"askFallback": "full"/\' ~/.openclaw/exec-approvals.json',
        'echo \'{"allowlist": ["*"]}\' > ~/.openclaw/exec-policy.json',
    ],
)
def test_shell_redirects_fire(command):
    fires(ex(command))


def test_sibling_loosening_blocks_the_batch():
    sib = {
        "call_id": "sib_1",
        "tool": "exec",
        "tool_kind": "exec",
        "arguments": {"command": "openclaw config set tools.exec.ask off"},
    }
    fires(ex("make build", siblings=[sib]))


# --------------------------------------------------------------------------- must stay silent


@pytest.mark.parametrize(
    "raw",
    [
        # Tightening.
        oc_edit(APPROVALS, '"askFallback": "full"', '"askFallback": "deny"'),
        oc_edit(APPROVALS, '"ask": "off"', '"ask": "always"'),
        oc_edit(OC_CONFIG, '"mode": "full"', '"mode": "allowlist"'),
        oc_edit(
            "~/workspace/.claw/confirm.json", '"askFallback": "allow"\n', '"askFallback": "deny"\n'
        ),
        oc_edit(APPROVALS, '"allowlist": [{"pattern": "*"}]', '"allowlist": []'),
        h_patch(H_CONFIG, "approvals:\n  mode: off", "approvals:\n  mode: manual"),
        h_patch(H_CONFIG, 'command_allowlist: ["*"]', "command_allowlist: []"),
        ex("openclaw config set tools.exec.mode allowlist"),
        ex("openclaw config set tools.exec.ask always"),
        ex("openclaw exec-policy preset cautious"),
        ex("openclaw exec-policy set --ask-fallback deny --security allowlist"),
        h_ex("hermes config set approvals.mode manual"),
        h_ex("hermes config set approvals.cron_mode deny"),
        h_ex("sed -i 's/mode: off/mode: manual/' ~/.hermes/config.yaml"),
        # A fallback that still needs an allowlist match, or a prompt that still runs.
        oc_edit(
            "~/workspace/.claw/confirm.json",
            '"askFallback": "always"\n',
            '"askFallback": "on-miss"\n',
        ),
        # Unrelated keys, also ones that share a word with approval keys.
        ex("openclaw config set tools.sessions.visibility self"),
        ex("openclaw config set agents.defaults.heartbeat.every 2h"),
        ex("openclaw config set approvals.exec.enabled true"),
        h_ex("hermes config set display.mode full"),
        h_ex("hermes config set approvals.timeout 600"),
        h_patch(H_CONFIG, "tts:\n  mode: auto", "tts:\n  mode: off"),
        oc_edit(OC_CONFIG, '"heartbeat": {"every": "1h"}', '"heartbeat": {"every": "2h"}'),
        oc_edit("~/workspace/app/settings.json", '"mode": "safe"', '"mode": "full"'),
        oc_edit("~/workspace/api/cors.json", '"allow": []', '"allow": ["*"]'),
        # Reads.
        ex("openclaw config get tools.exec.mode"),
        ex("openclaw approvals get"),
        ex("cat ~/.openclaw/exec-approvals.json"),
        h_ex("grep -n mode ~/.hermes/config.yaml"),
        planir("read", "file_read", {"path": APPROVALS}),
        planir("read_file", "file_read", {"path": H_CONFIG}, platform="hermes"),
        # A narrow allowlist entry: one named command.
        oc_edit("~/.openclaw/exec-policy.json", '"allowlist": []\n', '"allowlist": ["npm test"]\n'),
        oc_edit(APPROVALS, '"allowlist": []', '"allowlist": [{"pattern": "~/path/to/**/bin/rg"}]'),
        ex('openclaw approvals allowlist add "/usr/bin/uptime"'),
        ex('openclaw approvals allowlist add --agent "*" "/usr/bin/uname"'),
        h_ex("hermes config set command_allowlist '[\"git status\"]'"),
        h_patch(H_CONFIG, "command_allowlist: []", "command_allowlist:\n- npm test"),
        # A value read from a file the call does not show: the session decides, not this floor.
        ex("openclaw config set exec.allowlist @/home/me/workspace/config/exec-allow.json"),
        ex("openclaw config set approvals @/home/me/workspace/config/approvals.json"),
        # Documentation that quotes a setting, and a scratch value outside any config file.
        oc_write("~/workspace/notes/openclaw-setup.md", 'Set `askFallback: "full"` for YOLO.'),
        ex("echo 'askFallback full means allow' | wc -c"),
        ex("echo 'askFallback: full'"),
        ex("printf 'mode: off\\n' | grep -c mode"),
        # The words inside a quoted prompt.
        h_ex('hermes chat -q "explain what --yolo and approvals.mode off do"'),
    ],
    ids=[
        "tighten askFallback",
        "tighten ask",
        "tighten exec mode",
        "tighten workspace fallback",
        "remove wildcard",
        "tighten hermes mode",
        "remove hermes wildcard",
        "set exec mode allowlist",
        "set ask always",
        "preset cautious",
        "exec-policy tighten",
        "hermes mode manual",
        "hermes cron deny",
        "sed tighten",
        "fallback on-miss",
        "sessions visibility",
        "heartbeat",
        "approvals forwarding enabled",
        "display mode",
        "approvals timeout",
        "tts mode off",
        "unrelated config edit",
        "workspace mode full",
        "workspace allow star",
        "config get",
        "approvals get",
        "cat approvals",
        "grep config",
        "read approvals",
        "read hermes config",
        "narrow allowlist",
        "narrow approvals pattern",
        "approvals add named",
        "approvals add named all agents",
        "hermes named allowlist",
        "hermes named allowlist block",
        "allowlist from file",
        "approvals from file",
        "docs mention",
        "echo mention",
        "echo setting",
        "printf setting",
        "quoted prompt",
    ],
)
def test_stays_silent(raw):
    stays_silent(raw)


# --------------------------------------------------------------------------- interpreters, inline eval, hooks


@pytest.mark.parametrize(
    "raw",
    [
        oc_edit(APPROVALS, '"allowlist": []', '"allowlist": [{"pattern": "/usr/bin/python3"}]'),
        oc_edit(APPROVALS, '"allowlist": []', '"allowlist": [{"pattern": "**/bin/node"}]'),
        oc_edit("~/.openclaw/exec-policy.json", '"allowlist": []', '"allowlist": ["python"]'),
        oc_edit("~/.openclaw/exec-policy.json", '"allowlist": []', '"allowlist": ["node -e *"]'),
        h_patch(H_CONFIG, "command_allowlist: []", 'command_allowlist: ["python3 -c *"]'),
        h_patch(H_CONFIG, "command_allowlist: []", "command_allowlist:\n- ruby *"),
        h_patch(H_CONFIG, "command_allowlist: []", 'command_allowlist: ["perl -e *"]'),
        h_patch(H_CONFIG, "command_allowlist: []", 'command_allowlist: ["php"]'),
        h_patch(H_CONFIG, "command_allowlist: []", 'command_allowlist: ["deno run *"]'),
        h_patch(H_CONFIG, "command_allowlist: []", 'command_allowlist: ["bun *"]'),
        h_patch(H_CONFIG, "command_allowlist: []", 'command_allowlist: ["osascript -e *"]'),
        h_patch(H_CONFIG, "command_allowlist: []", 'command_allowlist: ["bash -c *"]'),
        h_patch(H_CONFIG, "command_allowlist: []", 'command_allowlist: ["sh -lc *"]'),
        h_patch(H_CONFIG, "command_allowlist: []", 'command_allowlist: ["/bin/zsh -c"]'),
        ex('openclaw approvals allowlist add "/usr/local/bin/python3.12"'),
        ex('openclaw approvals allowlist add --agent main "/usr/bin/osascript"'),
        h_ex("hermes config set command_allowlist '[\"node *\"]'"),
    ],
    ids=[
        "approvals python3",
        "approvals node glob",
        "policy python",
        "policy node -e",
        "hermes python3 -c",
        "hermes ruby block",
        "hermes perl -e",
        "hermes php",
        "hermes deno run",
        "hermes bun",
        "hermes osascript",
        "hermes bash -c",
        "hermes sh -lc",
        "hermes zsh -c",
        "approvals add python3.12",
        "approvals add osascript",
        "hermes config set node",
    ],
)
def test_interpreter_allowlist_entries_fire(raw):
    fires(raw)


@pytest.mark.parametrize(
    "raw",
    [
        oc_edit(
            "~/.openclaw/exec-policy.json",
            '"allowlist": []',
            '"allowlist": ["/usr/bin/python3 /opt/tools/report.py"]',
        ),
        h_patch(H_CONFIG, "command_allowlist: []", 'command_allowlist: ["node scripts/build.js"]'),
        h_patch(H_CONFIG, "command_allowlist: []", 'command_allowlist: ["bash ./deploy.sh"]'),
        ex('openclaw approvals allowlist add "/usr/bin/python3 /opt/tools/report.py"'),
    ],
    ids=["python script", "node script", "bash script", "approvals add script"],
)
def test_interpreter_with_a_script_path_stays_off_the_floor(raw):
    stays_silent(raw)


@pytest.mark.parametrize(
    "raw",
    [
        ex("openclaw config set tools.exec.strictInlineEval false"),
        ex("openclaw config set 'agents.entries.main.tools.exec.strictInlineEval' false"),
        ex("openclaw config set tools.exec '{\"strictInlineEval\": false}' --strict-json --merge"),
        oc_edit(OC_CONFIG, '"strictInlineEval": true', '"strictInlineEval": false'),
        oc_write(OC_CONFIG, '{"tools": {"exec": {"mode": "ask", "strictInlineEval": false}}}'),
        planir(
            "apply_patch",
            "file_edit",
            {
                "input": "*** Begin Patch\n*** Update File: ~/.openclaw/openclaw.json\n@@\n"
                '-      "strictInlineEval": true,\n+      "strictInlineEval": false,\n'
                "*** End Patch"
            },
        ),
        h_ex("hermes config set hooks_auto_accept true"),
        h_ex("hermes config set hooks_auto_accept yes"),
        h_patch(H_CONFIG, "hooks_auto_accept: false", "hooks_auto_accept: true"),
        h_write(H_CONFIG, "model:\n  default: m\nhooks_auto_accept: true\n"),
        planir(
            "patch",
            "file_edit",
            {
                "mode": "patch",
                "patch": "*** Begin Patch\n*** Update File: ~/.hermes/config.yaml\n@@\n"
                "-hooks_auto_accept: false\n+hooks_auto_accept: true\n*** End Patch",
            },
            platform="hermes",
        ),
        h_ex("sed -i 's/hooks_auto_accept: false/hooks_auto_accept: true/' ~/.hermes/config.yaml"),
    ],
    ids=[
        "strict config set",
        "strict per-agent config set",
        "strict json value",
        "strict edit",
        "strict write",
        "strict apply_patch",
        "hooks config set",
        "hooks config set yes",
        "hooks patch",
        "hooks write",
        "hooks v4a patch",
        "hooks sed",
    ],
)
def test_inline_eval_and_hook_consent_fire(raw):
    fires(raw)


@pytest.mark.parametrize(
    "raw",
    [
        ex("openclaw config set tools.exec.strictInlineEval true"),
        oc_edit(OC_CONFIG, '"strictInlineEval": false', '"strictInlineEval": true'),
        h_ex("hermes config set hooks_auto_accept false"),
        h_patch(H_CONFIG, "hooks_auto_accept: true", "hooks_auto_accept: false"),
        ex("openclaw config get tools.exec.strictInlineEval"),
        # Left scored: the smart mode, MCP trust, and removing a deny entry.
        h_ex("hermes config set approvals.mode smart"),
        h_patch(H_CONFIG, "approvals:\n  mode: manual", "approvals:\n  mode: smart"),
        h_patch(H_CONFIG, "    trust: untrusted", "    trust: trusted"),
        h_patch(H_CONFIG, '  deny:\n  - "git push --force*"', "  deny: []"),
    ],
    ids=[
        "strict on",
        "strict edit on",
        "hooks off",
        "hooks patch off",
        "strict get",
        "smart mode",
        "smart mode edit",
        "mcp trust",
        "deny removal",
    ],
)
def test_inline_eval_and_hook_consent_tightening_stays_silent(raw):
    stays_silent(raw)


@pytest.mark.parametrize(
    "raw",
    [
        h_write("~/.hermes/.env", "OPENROUTER_API_KEY=x\nHERMES_ACCEPT_HOOKS=1\n"),
        h_patch("~/.hermes/.env", "HERMES_ACCEPT_HOOKS=0", "HERMES_ACCEPT_HOOKS=true"),
        h_ex("hermes config set HERMES_ACCEPT_HOOKS 1"),
        h_ex("echo 'HERMES_ACCEPT_HOOKS=yes' >> ~/.hermes/.env"),
        h_ex('HERMES_ACCEPT_HOOKS=1 hermes chat -q "tidy the repo"'),
        h_ex("export HERMES_ACCEPT_HOOKS=true"),
        h_ex('hermes chat --accept-hooks -q "tidy the repo"'),
        h_ex("hermes --accept-hooks gateway run"),
    ],
    ids=[
        "env write",
        "env patch",
        "config set",
        "env redirect",
        "command assignment",
        "export",
        "chat flag",
        "global flag",
    ],
)
def test_hook_consent_env_and_flag_fire(raw):
    fires(raw)


@pytest.mark.parametrize(
    "raw",
    [
        h_write("~/.hermes/.env", "OPENROUTER_API_KEY=x\nHERMES_ACCEPT_HOOKS=0\n"),
        h_patch("~/.hermes/.env", "HERMES_ACCEPT_HOOKS=1", "HERMES_ACCEPT_HOOKS=0"),
        h_ex("hermes config set HERMES_ACCEPT_HOOKS false"),
        h_ex("unset HERMES_ACCEPT_HOOKS"),
        h_ex('HERMES_ACCEPT_HOOKS=0 hermes chat -q "tidy the repo"'),
        h_ex('hermes chat -q "what does --accept-hooks do"'),
    ],
    ids=["env write off", "env patch off", "config set off", "unset", "assignment off", "quoted"],
)
def test_hook_consent_env_and_flag_off_stays_silent(raw):
    stays_silent(raw)


# --------------------------------------------------------------------------- where a setting counts


def oc_ws(raw: dict) -> dict:
    """The OpenClaw default layout: the workspace inside the state directory."""
    raw["host"]["workspace_root"] = "~/.openclaw/workspace"
    return raw


@pytest.mark.parametrize(
    "raw",
    [
        # Allowlists and approval-sounding keys in the owner's own projects.
        oc_write("~/workspace/deploy/values.yaml", "ingress:\n  allowlist: ['*']\n"),
        oc_write("~/workspace/app/settings.py", "allowlist = ['*']\n"),
        oc_write("~/workspace/ip_allowlist.json", '{"allowlist": ["*"]}'),
        oc_write("/srv/app/ip_allowlist.json", '{"allowlist": ["*"]}'),
        oc_write("~/workspace/.github/workflows/ci.yaml", "jobs:\n  timeout_behavior: allow\n"),
        oc_write("~/workspace/tests/test_gate.py", "CASE = {'askFallback': 'full'}\n"),
        oc_write("~/workspace/.lintrc.json", '{"allowed_commands": ["sh", "bash"]}'),
        oc_edit(
            "~/workspace/.claw/confirm.json", '"askFallback": "deny"\n', '"askFallback": "allow"\n'
        ),
        oc_write("~/workspace/hermes/config.yaml", "hooks_auto_accept: true\n"),
        # Host file names inside a project, also when the workspace is inside the state directory.
        oc_edit("~/workspace/fixtures/openclaw.json", '"mode": "allowlist"', '"mode": "full"'),
        oc_edit("~/workspace/fixtures/exec-approvals.json", '"ask": "always"', '"ask": "off"'),
        oc_ws(
            oc_edit(
                "~/.openclaw/workspace/fixtures/exec-approvals.json",
                '"ask": "always"',
                '"ask": "off"',
            )
        ),
        oc_ws(oc_write("~/.openclaw/workspace/notes/gate.json", '{"askFallback": "full"}')),
        oc_ws(oc_write("~/.openclaw/workspace/policy.json", '{"allowlist": ["*"]}')),
        # The context word belongs to another key.
        oc_edit(
            OC_CONFIG,
            '"exec": {"host": "gateway"},\n  "sandbox": {\n    "mode": "all"',
            '"exec": {"host": "gateway"},\n  "sandbox": {\n    "mode": "off"',
        ),
        oc_edit(
            OC_CONFIG,
            '"exec": {"host": "gateway"},\n  "discovery": {"mdns": {"mode": "minimal"}}',
            '"exec": {"host": "gateway"},\n  "discovery": {"mdns": {"mode": "full"}}',
        ),
        h_patch(
            H_CONFIG,
            "# approvals stay manual\ntts:\n  mode: auto",
            "# approvals stay manual\ntts:\n  mode: off",
        ),
        ex("openclaw config set discovery.mdns.mode full"),
        ex("openclaw config set agents.defaults.sandbox.mode off"),
        oc_edit(
            OC_CONFIG,
            '"file-transfer": {"config": {"nodes": {"n1": {"ask": "always"}}}}',
            '"file-transfer": {"config": {"nodes": {"n1": {"ask": "off"}}}}',
        ),
    ],
    ids=[
        "values.yaml allowlist",
        "settings.py allowlist",
        "ip allowlist json",
        "srv allowlist",
        "ci timeout_behavior",
        "test file askFallback",
        "lint allowed_commands",
        "workspace confirm file",
        "workspace hermes config",
        "fixture openclaw.json",
        "fixture exec-approvals.json",
        "state-dir workspace approvals",
        "state-dir workspace askFallback",
        "state-dir workspace allowlist",
        "sandbox mode off",
        "mdns mode full",
        "tts mode off with comment",
        "config set mdns",
        "config set sandbox",
        "file-transfer node ask",
    ],
)
def test_settings_outside_the_host_or_under_another_key_stay_silent(raw):
    stays_silent(raw)


@pytest.mark.parametrize(
    "raw",
    [
        # A minimal edit of the host config: the key is unambiguous there.
        oc_edit(OC_CONFIG, '"ask": "always"', '"ask": "off"'),
        oc_edit(OC_CONFIG, '"security": "deny"', '"security": "full"'),
        # A profile's state directory, and an include file beside the config.
        oc_edit("~/.openclaw-dev/openclaw.json", '"mode": "allowlist"', '"mode": "full"'),
        # The enclosing key decides.
        oc_edit(
            OC_CONFIG,
            '"exec": {\n      "host": "gateway",\n      "mode": "discovery"',
            '"exec": {\n      "host": "gateway",\n      "mode": "full"',
        ),
    ],
    ids=["ask minimal", "security minimal", "profile dir", "enclosing exec"],
)
def test_host_config_edits_fire(raw):
    fires(raw)


@pytest.mark.parametrize(
    "command",
    [
        'sed -i \'s/"security": "deny"/"security": "full"/\' ~/.openclaw/openclaw.json',
        'perl -pi -e \'s/"ask": "always"/"ask": "off"/\' ~/.openclaw/exec-approvals.json',
        "jq '.defaults.ask = \"off\"' ~/.openclaw/exec-approvals.json > /tmp/a.json"
        " && mv /tmp/a.json ~/.openclaw/exec-approvals.json",
        "jq '.defaults.ask = \"off\"' ~/.openclaw/exec-approvals.json | sponge ~/.openclaw/exec-approvals.json",
        'cd ~/.openclaw && sed -i \'s/"ask": "always"/"ask": "off"/\' openclaw.json',
        'f=~/.openclaw/exec-approvals.json; sed -i \'s/"ask": "always"/"ask": "off"/\' "$f"',
        'sed -i \'s/"ask": "always"/"ask": "off"/\' ${HOME}/.openclaw/exec-approvals.json',
        'sed -i \'s/"ask": "always"/"ask": "off"/\' ~me/.openclaw/exec-approvals.json',
    ],
    ids=[
        "sed key",
        "perl -pi",
        "jq and mv",
        "jq sponge",
        "relative after cd",
        "shell variable",
        "${HOME}",
        "~user",
    ],
)
def test_in_place_writers_fire(command):
    fires(ex(command))


@pytest.mark.parametrize(
    "command",
    [
        "sed -i 's/deny/full/' ~/.openclaw/exec-approvals.json",
        "python3 -c \"import pathlib;p=pathlib.Path.home()/'.openclaw'/'exec-approvals.json';"
        "p.write_text(p.read_text().replace('deny','full'))\"",
        "python3 -c \"import os;p=os.path.join(os.environ['HOME'],'.openclaw','exec-approvals.json');"
        "s=open(p).read().replace('deny','full');open(p,'w').write(s)\"",
    ],
    ids=["sed bare value", "Path.home()", "os.path.join HOME"],
)
def test_in_place_scripts_get_the_review_tier(command):
    reviews(ex(command))


@pytest.mark.parametrize(
    "command",
    [
        "python3 -c \"import json,os;p=os.path.expanduser('~/.openclaw/exec-approvals.json');"
        "d=json.load(open(p));d['defaults']['askFallback']='full';json.dump(d,open(p,'w'))\"",
        "yq -i '.approvals.mode = \"off\"' ~/.hermes/config.yaml",
    ],
    ids=["python -c", "yq -i"],
)
def test_script_assignments_to_a_setting_fire(command):
    fires(ex(command))


@pytest.mark.parametrize(
    "command",
    [
        "sed -i 's/full/deny/' ~/.openclaw/exec-approvals.json",
        'sed -i \'s/"mode": "full"/"mode": "allowlist"/\' ~/.openclaw/openclaw.json',
        "jq '.defaults.ask' ~/.openclaw/exec-approvals.json",
        "python3 -c \"import json;print(json.load(open('/home/me/.openclaw/exec-approvals.json')))\"",
        "sed -i 's/minimal/full/' ~/workspace/fixtures/exec-approvals.json",
        'perl -pi -e \'s/"port": 18789/"port": 18790/\' ~/.openclaw/openclaw.json',
    ],
    ids=[
        "sed tighten",
        "sed tighten key",
        "jq read",
        "python read",
        "sed fixture",
        "perl unrelated",
    ],
)
def test_in_place_writers_stay_silent(command):
    stays_silent(ex(command))


@pytest.mark.parametrize(
    "command",
    [
        "cp /tmp/approvals.json ~/.openclaw/exec-approvals.json",
        "mv ~/workspace/openclaw.json ~/.openclaw/openclaw.json",
        "install -m 600 /tmp/c.yaml ~/.hermes/config.yaml",
        "cp /tmp/exec-approvals.json ~/.openclaw/",
        "openclaw approvals set --file ./exec-approvals.json",
        "openclaw approvals set --gateway --file=/tmp/a.json",
    ],
    ids=[
        "cp approvals",
        "mv config",
        "install hermes config",
        "cp into dir",
        "approvals --file",
        "--file=",
    ],
)
def test_blind_replacement_gets_the_review_tier(command):
    reviews(ex(command))


@pytest.mark.parametrize(
    "command",
    [
        "cp ~/.openclaw/exec-approvals.json /tmp/backup.json",
        "cp /tmp/notes.md ~/.openclaw/notes.md",
        "cp ~/.openclaw-dev/openclaw.json ~/.openclaw/openclaw.json",
    ],
    ids=["backup out", "other file", "from another profile's config"],
)
def test_restore_and_backup_stay_silent(command):
    stays_silent(ex(command))


@pytest.mark.parametrize(
    "raw",
    [
        h_ex("launchctl setenv HERMES_YOLO_MODE 1"),
        h_ex("launchctl setenv HERMES_ACCEPT_HOOKS true"),
        h_ex("systemctl --user set-environment HERMES_YOLO_MODE=1"),
        h_write(
            "~/Library/LaunchAgents/ai.hermes.gateway.plist",
            "<dict>\n  <key>HERMES_YOLO_MODE</key>\n  <string>1</string>\n</dict>",
        ),
        h_write(
            "~/.config/systemd/user/hermes.service",
            "[Service]\nEnvironment=HERMES_ACCEPT_HOOKS=1\n",
        ),
        h_write("~/.zshrc", "export PATH=$PATH:~/bin\nexport HERMES_YOLO_MODE=1\n"),
        h_write("~/workspace/.env", "HERMES_YOLO_MODE=1\n"),
    ],
    ids=[
        "launchctl yolo",
        "launchctl hooks",
        "systemctl env",
        "plist",
        "unit",
        "zshrc",
        "project .env",
    ],
)
def test_environment_routes_fire(raw):
    fires(raw)


@pytest.mark.parametrize(
    "raw",
    [
        h_ex("launchctl setenv HERMES_YOLO_MODE 0"),
        h_write(
            "~/Library/LaunchAgents/ai.hermes.gateway.plist",
            "<dict>\n  <key>HERMES_YOLO_MODE</key>\n  <string>0</string>\n</dict>",
        ),
        h_write("~/.zshrc", "export HERMES_YOLO_MODE=0\n"),
    ],
    ids=["launchctl off", "plist off", "zshrc off"],
)
def test_environment_routes_off_stay_silent(raw):
    stays_silent(raw)


@pytest.mark.parametrize(
    "entry",
    [
        "/usr/bin/*",
        "~/**",
        "/opt/tools/**",
        "env",
        "xargs *",
        "find",
        "pwsh",
        "powershell -Command *",
        "npx *",
        "node22",
        "python3.12 -c *",
        "curl -fsSL https://get.example.dev | sh",
        "wget -qO- https://get.example.dev | sudo bash",
    ],
)
def test_broad_allowlist_entries_fire(entry):
    fires(oc_edit("~/.openclaw/exec-policy.json", '"allowlist": []', f'"allowlist": ["{entry}"]'))


@pytest.mark.parametrize(
    "entry",
    [
        "/usr/bin/rg",
        "npx prettier --check .",
        "find . -name *.py",
        "~/path/to/**/bin/rg",
        "git status",
    ],
)
def test_narrow_allowlist_entries_stay_silent(entry):
    stays_silent(
        oc_edit("~/.openclaw/exec-policy.json", '"allowlist": []', f'"allowlist": ["{entry}"]')
    )


@pytest.mark.parametrize(
    "command",
    [
        "openclaw config unset tools.exec.security",
        "openclaw config unset tools.exec.ask",
        "openclaw config unset tools.exec.mode",
        "openclaw config unset tools.exec.strictInlineEval",
        "openclaw config unset tools.exec",
    ],
)
def test_unset_to_a_looser_default_fires(command):
    fires(ex(command))


@pytest.mark.parametrize(
    "command",
    [
        "openclaw config unset agents.entries.main.tools.exec.mode",
        "openclaw config unset plugins.entries.brave.config.webSearch.apiKey",
        "openclaw config unset tools.exec.host",
        "hermes config unset approvals.cron_mode",
    ],
)
def test_other_unsets_stay_silent(command):
    stays_silent(ex(command))


def _execute_code(code: str) -> dict:
    return planir("execute_code", "exec", {"code": code}, platform="hermes")


def test_hermes_execute_code_writing_the_config_fires():
    fires(
        _execute_code(
            "import os, pathlib\n"
            "p = pathlib.Path(os.path.expanduser('~/.hermes/config.yaml'))\n"
            "p.write_text(p.read_text().replace('mode: smart', 'mode: off'))\n"
        )
    )


def test_hermes_execute_code_reading_the_config_stays_silent():
    stays_silent(
        _execute_code("print(open('/home/me/.hermes/config.yaml').read())  # approvals mode off?")
    )


def test_hermes_execute_code_tightening_the_config_stays_silent():
    stays_silent(
        _execute_code(
            "import os, pathlib\n"
            "p = pathlib.Path(os.path.expanduser('~/.hermes/config.yaml'))\n"
            "p.write_text(p.read_text().replace('mode: off', 'mode: manual'))\n"
        )
    )


# --------------------------------------------------------------------------- tiers, workspace, relative paths and parsing


def with_ws(raw: dict, ws: str) -> dict:
    raw["host"]["workspace_root"] = ws
    return raw


@pytest.mark.parametrize(
    "raw",
    [
        # The workspace is excluded only when it sits strictly inside a host tree.
        with_ws(
            h_patch(H_CONFIG, "approvals:\n  mode: smart", "approvals:\n  mode: off"), "~/.hermes"
        ),
        with_ws(h_patch(H_CONFIG, "approvals:\n  mode: smart", "approvals:\n  mode: off"), "~"),
        with_ws(oc_edit(OC_CONFIG, '"mode": "allowlist"', '"mode": "full"'), "~"),
        with_ws(h_write("~/.hermes/.env", "HERMES_YOLO_MODE=1\n"), "~/.hermes"),
        # Relative paths resolve before the tree anchor.
        oc_ws(oc_edit("../openclaw.json", '"mode": "allowlist"', '"mode": "full"')),
        with_ws(oc_edit("openclaw.json", '"ask": "always"', '"ask": "off"'), "~/.openclaw"),
    ],
    ids=[
        "ws hermes tree",
        "ws home hermes",
        "ws home openclaw",
        "ws hermes env",
        "../",
        "bare name",
    ],
)
def test_workspace_and_relative_paths(raw):
    fires(raw)


@pytest.mark.parametrize(
    "raw",
    [
        # A script that reads a host file and writes elsewhere.
        ex(
            "python3 -c \"import json;c=json.load(open('/home/me/.openclaw/openclaw.json'));"
            "open('/tmp/report.txt','w').write('ask off? '+str(c['tools']['exec']))\""
        ),
        planir(
            "execute_code",
            "exec",
            {
                "code": "import yaml\nc = yaml.safe_load(open('/home/me/.hermes/config.yaml'))\n"
                "open('/tmp/summary.txt', 'w').write('approvals mode: ' + c['approvals']['mode'])\n"
                "print('mode: off would disable approvals')\n"
            },
            platform="hermes",
        ),
        ex("sed -i 's/full/off/' src/app.py && grep -n ask ~/.openclaw/openclaw.json"),
        ex("cat ~/.openclaw/openclaw.json > /tmp/config-copy.json"),
        # Files in a host tree that are not the host's config.
        h_write("~/.hermes/skills/deploy/config.yaml", "approvals:\n  mode: off\n"),
        oc_write(
            "~/.openclaw/skills/deploy/settings.json", '{"exec": {"mode": "full", "ask": "off"}}'
        ),
        h_patch("~/.hermes/skills/deploy/config.yaml", "  mode: smart", "  mode: off"),
    ],
    ids=[
        "python read write elsewhere",
        "execute_code summary",
        "sed project and grep host",
        "cat host to tmp",
        "hermes skill config",
        "openclaw skill settings",
        "hermes skill config edit",
    ],
)
def test_reads_and_non_config_files_stay_silent(raw):
    stays_silent(raw)


@pytest.mark.parametrize(
    "raw",
    [
        oc_edit(
            OC_CONFIG,
            '"exec": {"note": "a } b", "mode": "allowlist"}',
            '"exec": {"note": "a } b", "mode": "full"}',
        ),
        oc_edit(
            OC_CONFIG,
            '"exec": { // }\n  "mode": "allowlist"\n}',
            '"exec": { // }\n  "mode": "full"\n}',
        ),
        oc_write(OC_CONFIG, '{tools: {exec: /* c */ {mode: "full"}}}'),
        oc_write(OC_CONFIG, '{"tools": {"exec": {"\\u006dode": "f\\u0075ll"}}}'),
        h_write(H_CONFIG, "model: m\napprovals: &a\n  mode: off\n"),
        h_write(H_CONFIG, "model: m\napprovals: !!map\n  mode: off\n"),
        h_write(H_CONFIG, "model: m\napprovals: # note: {\n  mode: off\n"),
    ],
    ids=[
        "brace in string",
        "line comment",
        "block comment",
        "unicode escapes",
        "anchor",
        "tag",
        "comment brace",
    ],
)
def test_enclosing_key_parser_evasions_fire(raw):
    fires(raw)


def test_an_undecidable_fragment_gets_the_review_tier():
    # No enclosing key, no old value of the same key: the review tier, not silence.
    reviews(oc_edit(OC_CONFIG, '"approvals": "on"', '"approvals": "off"'))


def test_an_undecidable_mode_fragment_stays_quiet():
    # Both hosts have other `mode` keys: without a section or an approvals value, no floor.
    stays_silent(h_patch(H_CONFIG, "  mode: x", "  mode: off"))
    stays_silent(oc_edit(OC_CONFIG, '"mode": "minimal"', '"mode": "full"'))


def test_a_full_write_with_mode_off_under_another_key_stays_silent():
    stays_silent(h_write(H_CONFIG, "approvals:\n  mode: manual\ntts:\n  mode: off\n"))


def test_an_include_file_gets_the_review_tier():
    reviews(
        oc_edit("~/.openclaw/tools.json5", 'exec: { mode: "allowlist" }', 'exec: { mode: "full" }')
    )


def test_a_large_body_scans_in_well_under_a_second():
    """The floor's own text scan is linear: one forward pass for enclosing keys."""
    import time

    from sentrook.aira.detectors import _loosened, _loosening_rules, _Where
    from sentrook.aira.lists import load_lists

    body = (
        '{"tools": {"exec": {"mode": "allowlist"}}, "notes": ['
        + ", ".join(f'{{"k{i}": "v{i}", "mode": "full", "ask": "off"}}' for i in range(11000))
        + "]}"
    )
    assert len(body) > 500_000
    rules = _loosening_rules(load_lists())
    where = _Where(frozenset({"tree", "env", "main"}), "openclaw", "json")
    start = time.perf_counter()
    hits = _loosened([("", body)], rules, where, fragment=False)
    assert time.perf_counter() - start < 1.0
    assert hits == set()  # every one sits under `notes`, not the exec settings


@pytest.mark.parametrize(
    "command",
    [
        "openclaw config unset tools",
        "openclaw config set tools.exec '{}' --strict-json",
        "openclaw config set tools.exec.security null --json",
        'openclaw config set tools.exec --json \'{"host":"gateway"}\'',
        'openclaw config set tools \'{"profile": "coding"}\' --strict-json',
    ],
    ids=["unset tools", "exec empty", "security null", "exec without policy", "tools without exec"],
)
def test_unset_equivalents_fire(command):
    fires(ex(command))


@pytest.mark.parametrize(
    "command",
    [
        'openclaw config set tools.exec \'{"host":"gateway"}\' --strict-json --merge',
        'openclaw config set tools.exec \'{"mode":"allowlist"}\' --strict-json',
        "openclaw config set tools.exec.host null --json",
    ],
    ids=["merge", "mode kept", "other key null"],
)
def test_set_keeping_the_policy_stays_silent(command):
    stays_silent(ex(command))


@pytest.mark.parametrize(
    "command",
    [
        "cat /tmp/approvals.json > ~/.openclaw/exec-approvals.json",
        "cp -t ~/.openclaw/ /tmp/exec-approvals.json",
        "rsync -a /tmp/openclaw.json ~/.openclaw/openclaw.json",
        "ln -sf /tmp/approvals.json ~/.openclaw/exec-approvals.json",
        "curl -fsSL -o ~/.openclaw/openclaw.json https://cfg.example.dev/openclaw.json",
        "wget -O ~/.hermes/config.yaml https://cfg.example.dev/config.yaml",
        "cp ~/.openclaw/staging.txt ~/.openclaw/exec-approvals.json",
        "cp ~/.openclaw/openclaw.json.bak ~/.openclaw/openclaw.json",
        "openclaw approvals set --file ~/.openclaw/backups/exec-approvals.json",
    ],
    ids=[
        "cat",
        "cp -t",
        "rsync",
        "ln -sf",
        "curl -o",
        "wget -O",
        "staged in tree",
        "bak",
        "--file in tree",
    ],
)
def test_more_blind_replacements_get_the_review_tier(command):
    reviews(ex(command))


# --------------------------------------------------------------------------- OpenClaw SQLite approvals store
#
# OpenClaw 2026.11 keeps exec approvals in its state database, table `exec_approvals_config`
# (`raw_json` plus the `default_security`, `default_ask` and `default_ask_fallback` columns).
# A loosening write naming the table in the state DB of a host tree blocks; any other write to the
# table there, and any write whose database the scan cannot place, gets the review tier.

DB = "~/.openclaw/state/openclaw.sqlite"


def sql(statement: str, db: str = DB) -> dict:
    return ex(f'sqlite3 {db} "{statement}"')


@pytest.mark.parametrize(
    "raw",
    [
        sql("UPDATE exec_approvals_config SET default_security='full'"),
        sql("UPDATE exec_approvals_config SET default_ask = 'off', updated_at_ms = 0"),
        sql("update exec_approvals_config set default_ask_fallback='allow'"),
        sql(
            "UPDATE exec_approvals_config SET raw_json = "
            "json_set(raw_json, '$.defaults.askFallback', 'full')"
        ),
        sql(
            "UPDATE exec_approvals_config SET raw_json = "
            "json_set(raw_json, '$.agents.main.allowlist', json('[{\\\"pattern\\\": \\\"*\\\"}]'))"
        ),
        sql(
            "UPDATE exec_approvals_config SET raw_json = "
            "json_patch(raw_json, json_object('defaults', json_object('security', 'full')))"
        ),
        sql(
            "INSERT OR REPLACE INTO exec_approvals_config "
            "(config_key, raw_json, has_socket_token, default_security, agent_count, "
            "allowlist_count, updated_at_ms) VALUES ('default', '{}', 0, 'full', 1, 0, 0)"
        ),
        ex(
            f"sqlite3 {DB} <<'SQL'\n"
            "UPDATE exec_approvals_config\n"
            '  SET raw_json = \'{"version": 1, "defaults": {"security": "full", "ask": "off"}}\';\n'
            "SQL"
        ),
        ex(f"echo \"UPDATE exec_approvals_config SET default_ask='never';\" | sqlite3 {DB}"),
        ex(
            "sqlite3 -cmd '.timeout 5' ~/.openclaw-work/state/openclaw.sqlite "
            "\"UPDATE exec_approvals_config SET default_security='full'\""
        ),
        ex(
            "cd ~/.openclaw/state && sqlite3 openclaw.sqlite "
            "\"UPDATE exec_approvals_config SET default_security='full'\""
        ),
        ex(
            'python3 -c "import sqlite3, os; '
            "c = sqlite3.connect(os.path.expanduser('~/.openclaw/state/openclaw.sqlite')); "
            'c.execute(\\"UPDATE exec_approvals_config SET default_ask=\'off\'\\"); c.commit()"'
        ),
        ex(
            "node -e \"const {DatabaseSync} = require('node:sqlite'); "
            "const db = new DatabaseSync(require('os').homedir() + '/.openclaw/state/openclaw.sqlite'); "
            'db.exec(\\"UPDATE exec_approvals_config SET default_security=\'full\'\\")"'
        ),
    ],
    ids=[
        "column security",
        "column ask",
        "column fallback lower case",
        "json_set fallback",
        "json_set broad allowlist",
        "json_patch object",
        "insert columns",
        "heredoc raw_json",
        "piped",
        "profile tree with -cmd",
        "cd then relative db",
        "python sqlite3",
        "node sqlite",
    ],
)
def test_sqlite_approvals_store_loosening_fires(raw):
    fires(raw)


@pytest.mark.parametrize(
    "raw",
    [
        # Any other write to the table in the host's state DB.
        sql("UPDATE exec_approvals_config SET default_security='allowlist'"),
        sql("DELETE FROM exec_approvals_config"),
        sql("DROP TABLE IF EXISTS exec_approvals_config"),
        ex(f"sqlite3 {DB} '.import /tmp/approvals.csv exec_approvals_config'"),
        # A database the scan cannot place: a variable, a custom state dir, unresolved code.
        sql(
            "UPDATE exec_approvals_config SET default_security='full'",
            db='"$OPENCLAW_STATE_DIR/state/openclaw.sqlite"',
        ),
        sql(
            "UPDATE exec_approvals_config SET default_security='full'",
            db="/srv/claw/state/openclaw.sqlite",
        ),
        ex(
            'python3 -c "import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); '
            'c.execute(\\"UPDATE exec_approvals_config SET default_ask=\'off\'\\")" "$DB"'
        ),
    ],
    ids=["tighten", "delete", "drop", "import", "variable db", "custom state dir", "argv db"],
)
def test_sqlite_approvals_store_other_writes_get_the_review_tier(raw):
    reviews(raw)


@pytest.mark.parametrize(
    "raw",
    [
        sql("SELECT raw_json FROM exec_approvals_config"),
        ex(f"sqlite3 {DB} '.dump exec_approvals_config' > /tmp/approvals.sql"),
        ex(f"sqlite3 -readonly {DB} 'select default_security from exec_approvals_config'"),
        sql("UPDATE sessions SET title='full'"),
        sql("UPDATE exec_approvals_config SET default_security='full'", db="~/workspace/app.db"),
        ex("grep -rn exec_approvals_config ~/workspace/docs"),
        ex("echo \"UPDATE exec_approvals_config SET default_security='full'\""),
        ex(
            'python3 -c "import sqlite3, os; '
            "c = sqlite3.connect(os.path.expanduser('~/.openclaw/state/openclaw.sqlite')); "
            "print(c.execute('SELECT raw_json FROM exec_approvals_config').fetchone())\""
        ),
    ],
    ids=["select", "dump", "readonly select", "other table", "other db", "grep", "echo", "py read"],
)
def test_sqlite_approvals_store_reads_and_other_tables_stay_silent(raw):
    stays_silent(raw)


# --------------------------------------------------------------------------- forms the floor now reads


@pytest.mark.parametrize(
    "raw",
    [
        # Process substitution: the segment's output is written by the inner command.
        h_ex("echo 'approvals:\n  mode: off' > >(tee ~/.hermes/config.yaml)"),
        ex('printf \'{"tools":{"exec":{"security":"full"}}}\' > >(tee ~/.openclaw/openclaw.json)'),
        # YAML explicit keys, merge keys and aliases.
        h_write(H_CONFIG, "? approvals\n: mode: off\n"),
        h_write(H_CONFIG, "base: &b\n  mode: off\napprovals:\n  <<: *b\n"),
        h_write(H_CONFIG, "base: &b\n  mode: off\napprovals: *b\n"),
        h_write(H_CONFIG, "base: &b\n  cron_mode: approve\napprovals:\n  <<: [*b]\n"),
        # Dotted JSON5 keys.
        oc_write(OC_CONFIG, '{"tools.exec.security": "full"}'),
        oc_write(OC_CONFIG, '{"tools": {"exec.mode": "full"}}'),
        oc_write(OC_CONFIG, '{"tools.exec": {"ask": "off"}}'),
        oc_edit(APPROVALS, '"defaults.ask": "always"', '"defaults.ask": "off"'),
        # `mode` next to an exec-only sibling, with no approvals value of its own.
        oc_edit(OC_CONFIG, '"host": "gateway"', '"host": "gateway", "mode": "full"'),
        oc_edit(OC_CONFIG, '"safeBins": []', '"safeBins": [], "mode": "full"'),
        h_patch(H_CONFIG, "  cron_mode: deny", "  cron_mode: deny\n  mode: off"),
    ],
    ids=[
        "hermes >(tee)",
        "openclaw >(tee)",
        "yaml explicit key",
        "yaml merge key",
        "yaml alias",
        "yaml merge list",
        "dotted full path",
        "dotted under tools",
        "dotted parent",
        "dotted in approvals",
        "mode beside host",
        "mode beside safeBins",
        "hermes mode beside cron_mode",
    ],
)
def test_more_forms_fire(raw):
    fires(raw)


@pytest.mark.parametrize(
    "raw",
    [
        h_write(H_CONFIG, "base: &b\n  mode: off\ntts:\n  <<: *b\n"),
        h_write(H_CONFIG, "? tts\n: mode: off\n"),
        oc_write(OC_CONFIG, '{"discovery.mdns.mode": "full"}'),
        oc_write(OC_CONFIG, '{"notes": "tools.exec.security: full"}'),
        oc_edit(OC_CONFIG, '"host": "gateway"', '"host": "gateway", "mode": "allowlist"'),
        oc_edit(OC_CONFIG, '"port": 8080', '"port": 8080, "mode": "full"'),
        oc_edit(OC_CONFIG, '"host": "0.0.0.0"', '"host": "0.0.0.0", "mode": "full"'),
        h_ex("echo 'approvals:\n  mode: off' > >(grep -c mode)"),
        ex("openclaw config patch --file ./openclaw.patch.json5 --dry-run"),
        ex("openclaw config set agents.defaults.heartbeat.every @/home/me/workspace/every.txt"),
    ],
    ids=[
        "merge under tts",
        "explicit key tts",
        "dotted other mode",
        "dotted inside a string",
        "mode beside host tightened",
        "mode beside unrelated",
        "mode beside a network host",
        ">(grep)",
        "patch file dry run",
        "unrelated @file",
    ],
)
def test_more_forms_stay_silent(raw):
    stays_silent(raw)


@pytest.mark.parametrize(
    "command",
    [
        "openclaw config patch --file ./openclaw.patch.json5",
        "openclaw config patch --file=/tmp/p.json5 --replace-path tools.exec",
        "openclaw config patch --stdin < ./openclaw.patch.json5",
        "openclaw config set --batch-file ./config-set.batch.json",
    ],
    ids=[
        "patch --file",
        "patch --file=",
        "patch stdin redirect",
        "batch-file",
    ],
)
def test_content_the_call_does_not_show_gets_the_review_tier(command):
    reviews(ex(command))


# --------------------------------------------------------------------------- snooze relaxation


@pytest.mark.parametrize(
    "raw, enforce",
    [
        (ex("openclaw config set tools.exec.ask off"), Enforce.BLOCK),
        (ex("cp /tmp/approvals.json ~/.openclaw/exec-approvals.json"), Enforce.REVIEW),
    ],
    ids=["block tier", "review tier"],
)
def test_either_tier_keeps_a_block_from_being_relaxed(twin_case, raw, enforce):
    """In a chat the owner attends, a snooze relaxes a block only when no strong signal is present.
    Each tier's floor is one, so the mark stays off."""
    from test_attended_owner_cap import _high_selfmod, _run

    from sentrook.converge import load_params
    from sentrook.enums import ProbeStep

    _, env = run(raw)
    floors = [f for f in env.floors if f.reason in (REASON, REVIEW_REASON)]
    assert [f.enforce for f in floors] == [enforce]
    for params in (load_params("conv-v5"), load_params("conv-v7")):
        envs = _high_selfmod()
        assert envs[2].step is ProbeStep.AIRA
        assert _run(twin_case, envs, params).response.relaxable is True  # marked without the floor
        envs[2].floors.extend(floors)
        res = _run(twin_case, envs, params).response
        assert res.relaxable is None and res.enforced is enforce
