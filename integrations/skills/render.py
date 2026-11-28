"""Renders the agent skills and the always-loaded agent rules that both Sentrook plugins ship.

Each file in `TEMPLATES` is written once here and rendered per host, with the host's spelling of commands and
settings, into that plugin's folder (`HOSTS[host]["dir"]`): the two skills as `skills/<name>/SKILL.md`, the rules as
`agent-rules.txt`. The rendered files are committed, because the Hermes plugin installs straight from its folder; the
plugins' tests render them again and compare, so a template edit without a render fails CI.

A template holds plain text and placeholders, nothing else:
- `{{cmd VERB}}`: the chat command as the owner types it on the host (`/sentrook grant`, `/sentrook-grant`);
- `{{cli VERB}}`: its command-line form (`hermes sentrook grant`);
- `{{NAME}}`: the host's value for NAME (`values`), which may itself hold `{{cmd ...}}` and `{{cli ...}}`;
- `{{commands}}`: the host's commands, one line each, and `{{change_commands}}`: the ones that change what Sentrook
  allows, which the agent must never run.

    python3 integrations/skills/render.py          # write the rendered files
    python3 integrations/skills/render.py --check  # exit 1 when a rendered file is out of date
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

#: Template file -> where it goes inside a plugin's folder.
TEMPLATES: dict[str, str] = {
    "sentrook-guide.md": "skills/sentrook-guide/SKILL.md",
    "sentrook-setup.md": "skills/sentrook-setup/SKILL.md",
    "agent-rules.txt": "agent-rules.txt",
}

#: Command-line verbs with no chat form.
CLI_ONLY = ("verify", "login")

#: What each command does, in the agent's words: verb -> (arguments, summary). Shared by both hosts.
SUMMARIES: dict[str, tuple[str, str]] = {
    "status": (
        "",
        "plugin version, mode and thresholds, scan host, whether credentials are set, how many grants and "
        "bindings, snooze, held calls and where notices go. Anyone may run it",
    ),
    "help": ("", "lists the commands"),
    "history": (
        "[n]",
        "the last n scans (default 10, at most 50): time, session, tool, risk, what Sentrook did, the review",
    ),
    "why": (
        "[request_id|last]",
        "one scan in detail: risk, reasons, the hosts and files found, and the grant that would let calls like it "
        "through; with a held call's id, also the hold, the answers it offers and the grant Sentrook suggests",
    ),
    "report": (
        "[request_id|last] [--full|--github|--save]",
        "a report of a scan that looks wrong, to send to the Sentrook team: `--full` adds the exact request (send "
        "it privately), `--github` opens a public issue with the summary filled in, `--save` writes the report and "
        "the full record to a file to email",
    ),
    "grants": ("", "every grant in force, from config (read-only) and set by command"),
    "grant": (
        "<kind> <pattern> [flags]",
        "adds a grant: destination, file, provider, repo, credential or folder; for this session only (not cron jobs, "
        "subagents or other chats) unless `--persistent`; `--session <ref>` binds it to a session from history, "
        "`--allows read,write` (files only), `--follow origin/main` (folders in a git repository), `--expires 12h`",
    ),
    "revoke": ("<id>", "removes a grant set by command"),
    "bind": (
        "add|remove|list [channel]",
        "lists, adds or removes a channel binding: a channel this deployment normally delivers to",
    ),
    "snooze": (
        "[duration|off|status] [--all]",
        "lets review prompts through without asking in this session (`--all`: every session) for a while, default "
        "1h, at most 24h; in beta, a block in the owner's own chat asks instead, with a warning, except a change to "
        "Sentrook itself; never reviews Sentrook enforces or unattended runs; `off` ends it",
    ),
    "allow": (
        "<id> [now|later|always|all]",
        "answers a call held on an unattended run, by the id in Sentrook's notice, within 7 days: runs the cron job "
        "again now and lets the call through once in that run (`now`: even when the held run had already sent or "
        "written something; `later`: on the job's next scheduled run instead), or with `always` for 30 days on that "
        "job, where the notice offers it; `all`, on the id a run's end line names, also lets the calls that line "
        "listed through once in that run; Sentrook never runs the held call itself",
    ),
    "deny": (
        "<id>",
        "refuses a call held on a cron job, or on another run with a source, by the id in Sentrook's notice: that "
        "job or source is refused the same call for 30 days, with no more notices",
    ),
    "dismiss": (
        "<id>|all",
        "takes a held call (or all of them) off the waiting list without answering it, as if it had expired now: "
        "the call never runs and nothing is set, so a call like it is held again",
    ),
    "approve": ("<id>", "the same as allow (kept for one release)"),
    "passes": (
        "[revoke <id>]",
        "the passes and denials the owner's answers to held calls set, with their use counts; `revoke <id>` "
        "removes one",
    ),
    "notify": (
        "here|off|status",
        "where notices go: `here`, sent as a direct message to the agent, sends them to that chat; `off` stops "
        "them",
    ),
    "trust-chat": (
        "add|remove|list [<platform>:<chat id>] [--owner-only] [--confirm]",
        "a group chat or server channel where the owner knows every member: their messages count as from someone the "
        "owner trusts, not a stranger, but never as the owner's; members may answer its reviews unless it is added "
        "with `--owner-only`, which holds them for the owner; adding needs `--confirm`",
    ),
    "trust-user": (
        "add|remove|list [<platform>:<user id>] [--confirm]",
        "a person the owner knows: their messages count as from someone the owner trusts, in any chat, but never as "
        "the owner's; adding needs `--confirm`",
    ),
    "setup": (
        "[apply <code> [1,3] | discard <id>]",
        "lists what would stop Sentrook asking about routine work (channels the cron jobs deliver to, MCP servers, "
        "grants Sentrook suggested on reviews the owner approved), each described by Sentrook; the owner sets them "
        "with `apply` and the code the list ends with",
    ),
}

HOSTS: dict[str, dict] = {
    "hermes": {
        "dir": "integrations/hermes/plugin",
        "cli": "hermes sentrook",
        #: Every chat command, in the order the guide lists them.
        "commands": (
            "status",
            "help",
            "history",
            "why",
            "report",
            "grants",
            "grant",
            "revoke",
            "bind",
            "snooze",
            "allow",
            "deny",
            "dismiss",
            "approve",
            "passes",
            "notify",
            "attended",
            "trust-chat",
            "trust-user",
            "setup",
        ),
        #: Where a command's arguments or summary differ from the shared `SUMMARIES` on this host.
        "summaries": {
            "notify": (
                "here|off|status|<platform>",
                "where notices go: `here`, sent as a direct message to the agent, sends them to that chat (with a "
                "test notice); `<platform>` (on the machine) to that platform's home channel; `off` goes back to the "
                "`owner_channel` setting",
            ),
            "attended": (
                "add|remove|list [platform] [--confirm]",
                "the platforms with a person answering Hermes's approval prompts; adding one loosens Sentrook (a "
                "review there asks instead of holding the call), so it needs `--confirm`",
            ),
        },
        #: Chat commands typed as `/sentrook VERB` by anyone; the rest are owner commands, spelled the same here.
        "open": ("status", "help"),
        "owner_spelling": "/sentrook {}",
        #: The commands that change what Sentrook allows or where it reports, each a verb and any subcommand after it:
        #: the agent never runs them.
        "change": (
            "grant",
            "revoke",
            "bind",
            "snooze",
            "allow",
            "deny",
            "dismiss",
            "approve",
            "passes revoke",
            "notify",
            "attended add",
            "attended remove",
            "trust-chat add",
            "trust-chat remove",
            "trust-user add",
            "trust-user remove",
            "setup apply",
        ),
        "values": {
            "host": "Hermes",
            "approvers_setting": "`approvals.approvers` in Hermes's `config.yaml`",
            "trusted_roles": (
                "Hermes does not tell plugins which roles a member has, so a role cannot be trusted: trust the chat, "
                "or each person."
            ),
            "binding_form": (
                "On Hermes, write it with its platform, as `send_message` names the target: `discord:#daily-brief` "
                "or `discord:<channel id>`."
            ),
            "restart_after_install": (
                "After any install or update of the plugin, every Hermes process that was already running keeps "
                "the old plugin until it restarts: the owner restarts hermes-serve (the desktop app's backend), "
                "the gateway and the dashboard. Until they do, `verify` fails its `running build` line and "
                "`{{cmd status}}` says `restart needed`."
            ),
            "guide_skill": "`sentrook:sentrook-guide`",
            "setup_skill": "`sentrook:sentrook-setup`",
            "settings_place": "`plugins.entries.sentrook` in Hermes's `config.yaml`",
            "state_dir": "`sentrook/` in the Hermes home, such as `~/.hermes/sentrook/`",
            "approval_choices": (
                "Hermes shows its own buttons: **Once** runs this call; **Session** also lets the same action "
                "through for the rest of this session; **Always** lets it through from now on; **Deny** stops it. "
                "Where a grant would cover calls like this, the prompt says what Session and Always also set. On "
                "an MCP tool call the owner asked for, Always also covers that tool on that server for 30 days, at a "
                "similar risk and with no new warning; `{{cmd grants}}` lists these and `{{cmd revoke}} <id>` "
                "removes one."
            ),
            "always_answer": (
                "answering **Always** on an approval prompt that names a grant (it sets that grant for 30 days)"
            ),
            "unattended_runs": "cron jobs, webhooks, the API server, subagents of those",
            "run_sources": "a subagent's parent session, a webhook's route",
            "sourceless_runs": "the API server",
            "held_notice": (
                "The owner gets one notice on the chat where they sent `{{cmd notify}} here` (or the home channel "
                "of the platform in Sentrook's `owner_channel` setting); until one is set, nothing is sent and the "
                "call is still held."
            ),
            "background_saves": (
                "Hermes saves skills and memory in the background after a turn, with nobody there to answer a "
                "prompt, so Sentrook never asks about these saves. It judges each one against the conversation: a "
                "save it would review is let through, staged in Hermes's pending list (`/skills pending`, "
                "`/memory pending`) or held; a blocked one is not saved. A notice where held-call notices go "
                "says which."
            ),
            "owner_commands_where": (
                "Only the owner can run the commands below except `{{cmd status}}` and `{{cmd help}}`: in a direct "
                "message from an allowed user, or on the local terminal (`hermes chat`, or `hermes sentrook "
                "<command>` on the machine). Group chats and server channels are refused, private ones included."
            ),
            "owner_commands_where_short": "in a direct message to you, or on the machine",
            "cli_prefix_host": "hermes",
            "cli_wait": "Wait for it to finish; do not stop it early.",
            "tools_missing_hint": (
                "Hermes offers both tools in every chat, so a missing one means the running Hermes has an older "
                "plugin or none: ask the owner to run `{{cli verify}}` in a terminal on this machine and, after an "
                "update, to restart Hermes's services."
            ),
            "local_places": (
                "the terminal (`hermes chat`, or `hermes --tui` for the TUI) or the Hermes desktop app on the "
                "machine"
            ),
            "chat_app_reason": (
                "the owner commands setup ends with (such as `{{cmd setup}} apply`) are refused in group chats and "
                "server channels, and a long setup is easier to follow there. If the owner works with you from a group "
                "or server channel, also say: their own messages there count as theirs when they are listed in "
                "Hermes's allowed users, other members' messages and the channel history do not (unless the owner "
                'trusts the chat or the person: see "Group chats"), and reviews there ask in the channel, where '
                "anyone the bot lets in can answer, so a snooze and remembered grants only work in a direct message "
                "or the terminal"
            ),
            "approval_route": (
                "Hermes shows its approval buttons in the chat itself on Telegram, Discord, Slack and most other chat "
                "apps, with nothing to set up. Tell the owner, in one sentence, that a card with **Once**, "
                "**Session**, **Always** and **Deny** buttons is Sentrook asking. On Feishu the app needs its card "
                "callback set up first (Hermes's Feishu guide). If the owner says a card never arrived, check that "
                "they wrote from a direct message and that their account is on the platform's allowed users."
            ),
            "notice_explain": (
                "When a call is held, a scan fails on an unattended run, or a background save is held or let "
                "through, Sentrook sends the owner a notice. The owner chooses where by sending `{{cmd notify}} here` "
                "as a direct message to you on the chat where they want them (not in a group); Sentrook sends a test "
                "notice there, and `{{cmd notify}} status` says whether it arrived. Until then a scheduled job's held-call "
                "notice goes only to the job's own delivery chat, or to the owner's direct message where Sentrook can find "
                "one; other notices are not sent, and the call waits."
            ),
            "attended_explain": (
                "Approval prompts need a person to answer them. Chats, the Hermes TUI, the desktop app and the local "
                "terminal count as attended. A subagent of the owner's own chat, TUI or desktop app asks there too "
                "(not from the local terminal, where Hermes answers a subagent's prompt itself, nor while "
                "`delegation.subagent_auto_approve` is on); one nobody answers in time is held. The API server, "
                "cron jobs, webhooks and their subagents do not: a call there "
                "that needs review is held for the owner's `{{cmd allow}}` or `{{cmd deny}}` instead of asking. If a UI in front of the API "
                "server shows Hermes's approval prompts, the owner can add it with "
                "`{{cmd attended}} add api_server --confirm`. That loosens Sentrook, so only suggest it when the "
                "owner really answers prompts there."
            ),
        },
    },
    "openclaw": {
        "dir": "integrations/openclaw/plugin",
        "cli": "openclaw sentrook",
        "commands": (
            "status",
            "help",
            "history",
            "why",
            "report",
            "grants",
            "grant",
            "revoke",
            "bind",
            "snooze",
            "allow",
            "deny",
            "dismiss",
            "approve",
            "passes",
            "notify",
            "trust-chat",
            "trust-user",
            "setup",
        ),
        "open": ("status", "help"),
        "owner_spelling": "/sentrook-{}",
        "change": (
            "grant",
            "revoke",
            "bind",
            "snooze",
            "allow",
            "deny",
            "dismiss",
            "approve",
            "passes revoke",
            "notify",
            "trust-chat add",
            "trust-chat remove",
            "trust-user add",
            "trust-user remove",
            "setup apply",
        ),
        "values": {
            "host": "OpenClaw",
            "approvers_setting": "`channels.<app>.execApprovals.approvers` in `openclaw.json`",
            "trusted_roles": (
                "A chat role can be trusted too, with Sentrook's `trustedRoles` setting, which only the owner edits."
            ),
            "binding_form": (
                "On OpenClaw, write it with its platform, `discord:<channel id>` or `discord:#daily-brief`: it then "
                "applies to a send that names that platform, posts as an account the config has on it, or comes "
                "from a session on it. If a job's sends name none of these, write it as the send's own target, "
                "`channel:<channel id>`."
            ),
            "restart_after_install": (
                "After any install or update of the plugin, the running gateway keeps the old plugin until it "
                "restarts: the owner restarts it."
            ),
            "guide_skill": "`sentrook-guide`",
            "setup_skill": "`sentrook-setup`",
            "settings_place": "`plugins.entries.sentrook` in `openclaw.json`",
            "state_dir": "`sentrook/` in the OpenClaw state folder, such as `~/.openclaw/sentrook/`",
            "approval_choices": (
                "OpenClaw shows its own buttons: **Allow once** runs this call; **Allow always** appears only when "
                "the owner asked for the work and either a grant would cover calls like this (it also sets that "
                "grant for 30 days) or the call is an MCP tool's (it also covers that tool on that server for 30 "
                "days, at a similar risk and with no new warning; `{{cmd grants}}` lists these and `{{cmd revoke}} "
                "<id>` removes one); **Deny** stops it. Unanswered, a prompt in a chat denies the call after 5 "
                "minutes."
            ),
            "always_answer": (
                "answering **Allow always** on an approval card that offers it (it sets that grant for 30 days)"
            ),
            "unattended_runs": "cron jobs, heartbeats, subagents, webhooks",
            "run_sources": "a heartbeat's agent, a subagent's parent session",
            "sourceless_runs": "a webhook",
            "held_notice": (
                "The owner gets one notice as a direct message on the chat where they ran `{{cmd notify}} here`; "
                "until then, nothing is sent and the call is still held."
            ),
            "background_saves": (
                "OpenClaw saves skills and memory on its own (the Skill Workshop review, the memory flush, the "
                "skill collection review), with nobody there to answer a prompt, so Sentrook never asks about "
                "these saves. It judges each one against the conversation: a save it would review is let through, "
                "saved as a Skill Workshop draft for the owner, or held; a blocked one is not saved. A notice "
                "where held-call notices go says which."
            ),
            "owner_commands_where": (
                "`{{cmd status}}` and `{{cmd help}}` are open to anyone. The dashed commands are for the owner "
                "only: from a direct message by the owner, the Control UI, or `openclaw sentrook <command>` on the "
                "machine. They refuse in a group or channel room (a private server channel included), even from the "
                "owner, since everyone there would see the reply."
            ),
            "owner_commands_where_short": "as a direct message to you, in the Control UI, or on the machine",
            "cli_prefix_host": "openclaw",
            "tools_missing_hint": (
                "OpenClaw offers them only on the owner's own turns, and a tool profile or an allow or deny list in "
                "its config can hide them: ask the owner to run `{{cli verify}}` in a terminal on this machine, "
                "which names such a setting."
            ),
            "cli_wait": (
                "On OpenClaw an `openclaw sentrook` command can take half a minute or more to start: run it with a "
                "timeout of at least 90 seconds and wait for it to finish. If it still has not finished, carry on "
                "with the setup report and ask the owner to run it in a terminal; slow is not broken, so never tell "
                "the owner Sentrook hangs."
            ),
            "local_places": "the Control UI (`openclaw dashboard`) or the terminal (`openclaw tui`) on the machine",
            "chat_app_reason": (
                "until step 4 shows that approval cards reach this chat app, a step Sentrook asks about here is "
                "refused, which could leave you both stuck; once they do, cards work here as anywhere"
            ),
            "approval_route": (
                "OpenClaw shows Sentrook's approval cards in Discord, Telegram, WhatsApp and Signal only once that app "
                "is set up for them; until then, a call Sentrook asks about there is refused. Read what is set with "
                "`openclaw config get commands.ownerAllowFrom`, `openclaw config get channels.<app>.execApprovals` "
                "and `openclaw config get approvals.plugin`. The owner's approver account comes from "
                "`commands.ownerAllowFrom` (OpenClaw fills it when the owner approves the first pairing) or the app's "
                "`execApprovals.approvers`. For each chat app the owner uses that is not set, give the owner the "
                "commands, to run in a terminal on this machine:\n\n"
                "   - Discord (off until enabled):\n\n"
                "     ```\n"
                "     openclaw config set channels.discord.execApprovals.enabled true\n"
                "     ```\n\n"
                "   - Discord or Telegram, only when `commands.ownerAllowFrom` does not already name the owner on that "
                "app (Telegram's cards are on by default and need only this):\n\n"
                "     ```\n"
                "     openclaw config set channels.telegram.execApprovals.approvers '[\"<your Telegram user id>\"]'\n"
                "     ```\n\n"
                "   - WhatsApp or Signal: forward the cards to the chat the request came from (Signal also needs the "
                "owner in `channels.signal.allowFrom`):\n\n"
                "     ```\n"
                "     openclaw config set approvals.plugin.enabled true\n"
                "     openclaw config set approvals.plugin.mode session\n"
                "     ```\n\n"
                "   Slack needs nothing: the card shows in the same chat, for the accounts in Slack's `allowFrom`. If "
                "a command prints that the gateway needs a restart, the owner runs `openclaw gateway restart`. The "
                "approver is always the owner's own account, never anyone else's. In a group or channel room the "
                "cards go to the owner's direct messages."
            ),
            "notice_explain": (
                "When a call is held, a scan fails on an unattended run, or a background save is held, drafted or "
                "let through, Sentrook sends the owner a notice. The owner chooses where by sending "
                "`{{cmd notify}} here` as a direct message to you on the chat where they want them (not in a group "
                "or channel). Until then a scheduled job's held-call notice goes only to the job's own delivery chat, or to the "
                "owner's direct message where Sentrook can find one; other notices are not sent, and the call waits."
            ),
            "attended_explain": (
                "Approval prompts need a person to answer them. A direct chat with you (a DM, webchat or the Control "
                "UI) is attended. Group rooms, cron jobs, heartbeats and subagents are not: a review in a cron job, "
                "heartbeat or subagent holds the call for the owner's `{{cmd allow}}` or `{{cmd deny}}` instead of "
                "asking. That includes a subagent the owner's own chat started: OpenClaw cannot show a subagent's "
                "prompt, so its hold is bound to that chat. Which runs hold is set by Sentrook's "
                "`approval.scheduledIntentKinds` setting."
            ),
        },
    },
}

PLACEHOLDER = re.compile(r"\{\{(?:(cmd|cli) ([a-z-]+)|([a-z_]+))\}\}")


def chat(host: str, verb: str) -> str:
    """`verb` as the owner types it in a chat on `host`; `verb` may carry a word after it (`setup apply`)."""
    h = HOSTS[host]
    verb, _, more = verb.partition(" ")
    if verb not in h["commands"]:
        raise KeyError(f"{host} has no command {verb!r}")
    typed = f"/sentrook {verb}" if verb in h["open"] else h["owner_spelling"].format(verb)
    return f"{typed} {more}" if more else typed


def cli(host: str, verb: str) -> str:
    """`verb` as typed on the host's command line."""
    h = HOSTS[host]
    if verb not in CLI_ONLY and verb not in h["commands"]:
        raise KeyError(f"{host} has no command {verb!r}")
    return f"{h['cli']} {verb}"


def change_command(entry: str) -> str:
    """`verb [subcommand]` as a placeholder for the never-run list, in backticks."""
    verb, _, sub = entry.partition(" ")
    return f"`{{{{cmd {verb}}}}}{' ' + sub if sub else ''}`"


def summary_of(host: str, verb: str) -> tuple[str, str]:
    """(arguments, summary) for `verb` on `host`."""
    return HOSTS[host].get("summaries", {}).get(verb) or SUMMARIES[verb]


def values(host: str) -> dict[str, str]:
    h = HOSTS[host]
    lines = []
    for verb in h["commands"]:
        args, summary = summary_of(host, verb)
        usage = f"{{{{cmd {verb}}}}} {args}".rstrip()
        lines.append(f"- `{usage}`: {summary}.")
    return {
        **h["values"],
        "cli_prefix": h["cli"],
        "commands": "\n".join(lines),
        "change_commands": ", ".join(change_command(entry) for entry in h["change"]),
    }


def render(text: str, host: str) -> str:
    """`text` with every placeholder replaced by the host's value."""
    table = values(host)

    def sub(m: re.Match[str]) -> str:
        if m[1] == "cmd":
            return chat(host, m[2])
        if m[1] == "cli":
            return cli(host, m[2])
        return render(table[m[3]], host)

    return PLACEHOLDER.sub(sub, text)


def outputs() -> dict[Path, str]:
    """Every rendered file, by path, with its expected contents."""
    out: dict[Path, str] = {}
    for host, h in HOSTS.items():
        for template, rel in TEMPLATES.items():
            out[REPO / h["dir"] / rel] = render((HERE / template).read_text(), host)
    return out


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for path, text in outputs().items():
        if path.exists() and path.read_text() == text:
            continue
        if check:
            stale.append(path.relative_to(REPO))
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        print(f"wrote {path.relative_to(REPO)}")
    if stale:
        print("out of date (run python3 integrations/skills/render.py):")
        print("\n".join(f"  {p}" for p in stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
