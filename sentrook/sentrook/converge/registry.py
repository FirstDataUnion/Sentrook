"""Signal registry: every leaf signal, its tier, polarity and merge rule; and the
reason-code registry, a finite list of `domain.detail` codes with the plain-language text the review card shows.

Convergence only accepts contributions to registered signals. Unknown reason codes are tolerated (a
probe may add one before the registry catches up): a family or domain text covers them, or they have none.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import NamedTuple


class Merge(StrEnum):
    MAX = "max"
    MAX_OVER_SUBJECTS = "max_over_subjects"
    MIN = "min"


@dataclass(frozen=True)
class Signal:
    name: str
    tier: str
    merge: Merge
    higher_is_worse: bool
    description: str


SIGNALS: dict[str, Signal] = {
    s.name: s
    for s in (
        Signal(
            "suspicion.exposure",
            "suspicion",
            Merge.MAX,
            True,
            "Recent untrusted input contained agent-directed instructions",
        ),
        Signal(
            "suspicion.session_exposure",
            "suspicion",
            Merge.MAX,
            True,
            "Earlier in this session the agent read content carrying instructions aimed at it",
        ),
        Signal(
            "suspicion.untrusted_origin",
            "suspicion",
            Merge.MAX_OVER_SUBJECTS,
            True,
            "Key arguments came only from untrusted content",
        ),
        Signal(
            "suspicion.misalignment",
            "suspicion",
            Merge.MAX,
            True,
            "Call does not serve the owner's request",
        ),
        Signal("suspicion.concealment", "suspicion", Merge.MAX, True, "Call hides what it does"),
        Signal(
            "suspicion.overreach",
            "suspicion",
            Merge.MAX,
            True,
            "Call acts on more than the request covers, judged against what the agent read",
        ),
        Signal(
            "suspicion.distrust",
            "suspicion",
            Merge.MAX_OVER_SUBJECTS,
            True,
            "Entities are known-bad or unknown in a risky role",
        ),
        Signal(
            "suspicion.request_origin",
            "suspicion",
            Merge.MAX,
            True,
            "The request did not come from the owner",
        ),
        Signal(
            "suspicion.retry_after_denial",
            "suspicion",
            Merge.MAX,
            True,
            "Agent is retrying a denied action",
        ),
        Signal(
            "consequence.sensitivity",
            "consequence",
            Merge.MAX,
            True,
            "Value of the data or assets touched",
        ),
        Signal(
            "consequence.reach", "consequence", Merge.MAX, True, "Blast radius: location and extent"
        ),
        Signal(
            "consequence.irreversibility", "consequence", Merge.MAX, True, "Effect cannot be undone"
        ),
        Signal(
            "consequence.self_modification",
            "consequence",
            Merge.MAX,
            True,
            "Changes the agent's instructions, memory, config, scheduler, permissions or oversight",
        ),
        Signal(
            "confidence.coverage",
            "confidence",
            Merge.MIN,
            False,
            "Nothing truncated, unscanned, errored or unknown",
        ),
        Signal(
            "confidence.model_certainty",
            "confidence",
            Merge.MIN,
            False,
            "Jev answers were confident and not split",
        ),
    )
}

#: `confidence.agreement` is computed by convergence, never contributed.
COMPUTED_SIGNALS = ("confidence.agreement",)


class ReasonText(NamedTuple):
    """A reason in plain words for the review card: a clause in lower case with no full stop, which the plugin joins
    as "Because a, and b.". `subject` names the reason's subject entity as `{subject}`; `plain` is for a reason
    with none. Written for anyone, from the user's side: what the call does or what Sentrook noticed."""

    subject: str
    plain: str


#: Reason codes → card text. None for a reason that does not say why a call is risky: relief, gaps in what the scan
#: could check (`coverage.*`), split model answers (`agreement.*`), the attended-owner cap, and claims that only
#: lower the risk or never reach `reasons`.
REASONS: dict[str, ReasonText | None] = {
    "agreement.consequence_split": None,
    "agreement.suspicion_split": None,
    "artefact.credential_file_pushed": ReasonText(
        "it pushes {subject}, a file with passwords or keys",
        "it pushes a file with passwords or keys",
    ),
    "artefact.placeholder_in_write": ReasonText(
        "it writes a secret into {subject}",
        "it writes a secret into a file",
    ),
    "artefact.push_with_secret": ReasonText(
        "it pushes code that includes a secret",
        "it pushes code that includes a secret",
    ),
    "artefact.sensitive_basename_committed": ReasonText(
        "it commits {subject}, a sensitive file, to git",
        "it commits a sensitive file to git",
    ),
    "call.not_supported_by_request": ReasonText(
        "it does not follow from what you asked for",
        "it does not follow from what you asked for",
    ),
    "cap.attended_owner": None,
    "cap.unanswered_retry": None,
    "code.decode_to_shell": ReasonText(
        "it decodes hidden code and runs it",
        "it decodes hidden code and runs it",
    ),
    "code.fetch_to_shell": ReasonText(
        "it downloads code from {subject} and runs it straight away",
        "it downloads code and runs it straight away",
    ),
    "code.install_from_url": ReasonText(
        "it installs software straight from {subject}",
        "it installs software straight from a web address",
    ),
    "code.lookalike_installer": ReasonText(
        "{subject} looks like a copy of a well-known install site",
        "its code comes from a look-alike of a known install site",
    ),
    "code.lookalike_provider": ReasonText(
        "the tool server {subject} is one letter off from one used earlier",
        "its tool server is one letter off from one used earlier",
    ),
    "code.package_install": ReasonText(
        "it installs {subject}",
        "it installs a package",
    ),
    "code.param_injection": ReasonText(
        "it sends a shell command to a local service in a web address",
        "it sends a shell command to a local service in a web address",
    ),
    "code.registry_redirect": ReasonText(
        "it points the package installer at {subject} for future installs",
        "it points the package installer at a new source",
    ),
    "code.run_written_file": ReasonText(
        "it runs {subject}, which the agent wrote after downloading content",
        "it runs a file the agent wrote after downloading content",
    ),
    "code.steered_source": ReasonText(
        "it runs code from {subject}, named by content that tried to steer the agent",
        "it runs code from a site named by content that tried to steer the agent",
    ),
    "code.unvetted_package": ReasonText(
        "the package {subject} is unvetted and runs code when installed",
        "the package is unvetted and runs code when installed",
    ),
    "code.unvetted_source": ReasonText(
        "code from {subject} is unvetted and runs with the agent's access",
        "its code is unvetted and runs with the agent's access",
    ),
    "conceal.command_in_url": ReasonText(
        "it hides a shell command inside a web address",
        "it hides a shell command inside a web address",
    ),
    "conceal.encoded_payload": ReasonText(
        "it hides what it runs behind encoding",
        "it hides what it runs behind encoding",
    ),
    "conceal.obfuscated_command": ReasonText(
        "the command is written to hide what it runs",
        "the command is written to hide what it runs",
    ),
    "conceal.output_suppressed": ReasonText(
        "it hides the output of a network request",
        "it hides the output of a network request",
    ),
    "coverage.context": None,
    "coverage.input_too_large": None,
    "coverage.oracle_unavailable": None,
    "coverage.probe_failed": None,
    "coverage.trigger_unknown": None,
    "coverage.unknown_entities": None,
    "coverage.unknown_sender": None,
    "destroy.outside_scratch": ReasonText(
        "it deletes {subject}, outside the agent's work area",
        "it deletes files outside the agent's work area",
    ),
    "destroy.sql": ReasonText(
        "it runs a database command that deletes data",
        "it runs a database command that deletes data",
    ),
    "destroy.workspace_wide": ReasonText(
        "it deletes the whole workspace",
        "it deletes the whole workspace",
    ),
    "escalation.consequence_rising": ReasonText(
        "each recent step in this session went further than the last",
        "each recent step in this session went further than the last",
    ),
    "exfil.attachment": ReasonText(
        "it attaches {subject}, a sensitive file",
        "it attaches a sensitive file",
    ),
    "exfil.exec_egress": ReasonText(
        "it sends sensitive data to {subject}",
        "it sends sensitive data off this machine",
    ),
    "exfil.message_send": ReasonText(
        "the message carries sensitive data to {subject}",
        "the message carries sensitive data",
    ),
    "exfil.placeholder_in_argv": ReasonText(
        "it sends {subject}, which holds a secret",
        "it sends a secret",
    ),
    "exfil.raw_socket": ReasonText(
        "it sends sensitive data over a raw connection to {subject}",
        "it sends sensitive data over a raw network connection",
    ),
    "exfil.session_holds_sensitive": ReasonText(
        "it sends data from {subject}, which holds sensitive information",
        "it sends data out after the agent read sensitive data",
    ),
    "exfil.web_post": ReasonText(
        "it posts sensitive data to {subject}",
        "it posts sensitive data to a website",
    ),
    "exfil.web_query": ReasonText(
        "the web address it opens carries sensitive data to {subject}",
        "the web address it opens carries sensitive data",
    ),
    "exposure.authority": ReasonText(
        "content the agent just read claimed authority it lacks",
        "content the agent just read claimed authority it lacks",
    ),
    "exposure.instructions": ReasonText(
        "content the agent just read had instructions aimed at it",
        "content the agent just read had instructions aimed at it",
    ),
    "exposure.session_injected_content": ReasonText(
        "{subject} came from content that tried to steer the agent",
        "it uses content that tried to steer the agent",
    ),
    "exposure.session_tainted": ReasonText(
        "earlier, the agent read content aimed at steering it",
        "earlier, the agent read content aimed at steering it",
    ),
    "exposure.task_change": ReasonText(
        "content the agent just read tried to change its task",
        "content the agent just read tried to change its task",
    ),
    "extent.bulk_recipients": ReasonText(
        "it goes to many recipients at once",
        "it goes to many recipients at once",
    ),
    "extent.recursive": ReasonText(
        "it acts on a whole folder tree at once",
        "it acts on a whole folder tree at once",
    ),
    "extent.wildcard": ReasonText(
        "it acts on every file a wildcard matches",
        "it acts on every file a wildcard matches",
    ),
    "floor.guardrail_tampering": ReasonText(
        "it interferes with the agent's safety controls",
        "it interferes with the agent's safety controls",
    ),
    "floor.injected_content_used": ReasonText(
        "{subject} came from content that tried to steer the agent",
        "it uses content that tried to steer the agent",
    ),
    "floor.input_too_large": ReasonText(
        "this call is too large for Sentrook to check in full",
        "this call is too large for Sentrook to check in full",
    ),
    "floor.known_bad_entity": ReasonText(
        "{subject} is on Sentrook's known-bad list",
        "something this call uses is on Sentrook's known-bad list",
    ),
    "floor.lookalike_code_source": ReasonText(
        "{subject} supplies code and looks like a copy of a well-known name",
        "its code comes from a look-alike of a well-known name",
    ),
    "floor.sensitive_data_sent": ReasonText(
        "it sends {subject}, which holds sensitive data, off this machine",
        "it sends sensitive data off this machine",
    ),
    "floor.untrusted_code_execution": ReasonText(
        "it runs code from an untrusted source",
        "it runs code from an untrusted source",
    ),
    "guardrail.approval_loosening": ReasonText(
        "it lets later commands run without asking you",
        "it lets later commands run without asking you",
    ),
    "guardrail.approval_loosening_review": ReasonText(
        "it may let later commands run without asking you",
        "it may let later commands run without asking you",
    ),
    "guardrail.config_entry": ReasonText(
        "it edits Sentrook's settings",
        "it edits Sentrook's settings",
    ),
    "guardrail.gateway_stop": ReasonText(
        "it stops the agent's gateway service",
        "it stops the agent's gateway service",
    ),
    "guardrail.host_approvals": ReasonText(
        "it changes which commands run without asking you",
        "it changes which commands run without asking you",
    ),
    "guardrail.log_tamper": ReasonText(
        "it deletes or trims Sentrook's log",
        "it deletes or trims Sentrook's log",
    ),
    "guardrail.plugin_command": ReasonText(
        "it runs a Sentrook command that only you should run",
        "it runs a Sentrook command that only you should run",
    ),
    "guardrail.plugin_disable": ReasonText(
        "it turns off or removes Sentrook",
        "it turns off or removes Sentrook",
    ),
    "guardrail.tampering_review": ReasonText(
        "it may turn off or get around the agent's safety controls",
        "it may turn off or get around the agent's safety controls",
    ),
    "guardrail.state_dir_write": ReasonText(
        "it writes into Sentrook's own files",
        "it writes into Sentrook's own files",
    ),
    "jev.concealment": ReasonText(
        "it seems to hide what it does",
        "it seems to hide what it does",
    ),
    "jev.confidence_mean": None,
    "jev.irreversibility": ReasonText(
        "it would be hard to undo",
        "it would be hard to undo",
    ),
    "jev.reach": ReasonText(
        "its effects reach beyond the workspace",
        "its effects reach beyond the workspace",
    ),
    "jev.scope_overreach": ReasonText(
        "it does more than you asked for",
        "it does more than you asked for",
    ),
    "jev.self_modification": ReasonText(
        "it changes the agent's own setup",
        "it changes the agent's own setup",
    ),
    "jev.sensitivity": ReasonText(
        "it handles sensitive data",
        "it handles sensitive data",
    ),
    "lineage.filter_silences_security_notices": ReasonText(
        "it sets up a filter at {subject} that hides security alerts",
        "it sets up a filter that hides sign-in and security alerts",
    ),
    "lineage.listing_marks_irreplaceable": ReasonText(
        "the agent's own listing marks part of {subject} as irreplaceable",
        "the agent's own listing marks part of this as irreplaceable",
    ),
    "lineage.listing_marks_live_table": ReasonText(
        "the agent's own check shows this table holds live data",
        "the agent's own check shows this table holds live data",
    ),
    "lineage.lookalike_of_named_host": ReasonText(
        "{subject} looks like a site you named, but is a different one",
        "a site here looks like one you named, but is a different one",
    ),
    "lineage.lookalike_of_named_package": ReasonText(
        "{subject} looks like a package you named, but is a different one",
        "a package here looks like one you named, but is a different one",
    ),
    "lineage.lookalike_of_named_person": ReasonText(
        "{subject} is one letter off from a person you named",
        "a recipient is one letter off from a person you named",
    ),
    "lineage.moved_into_destroyed_tree": ReasonText(
        "the agent earlier moved {subject} into what this deletes",
        "the agent earlier moved files into what this deletes",
    ),
    "lineage.secret_carried_to_send": ReasonText(
        "the agent wrote a secret into {subject}, and this sends it",
        "the agent wrote a secret into a file this sends",
    ),
    "origin.agent_created_dirty_lineage": ReasonText(
        "the agent made {subject} after reading untrusted content",
        "the agent made this after reading untrusted content",
    ),
    "origin.agent_created_visible": None,
    "origin.agent_generated": ReasonText(
        "the agent chose {subject} without you naming it",
        "the agent chose this without you naming it",
    ),
    "origin.granted": None,
    "origin.host_configured_provider": None,
    "origin.lookalike_of_named_host": ReasonText(
        "{subject} looks like a site you named, but is a different one",
        "a site here looks like one you named, but is a different one",
    ),
    "origin.lookalike_of_named_package": ReasonText(
        "{subject} looks like a package you named, but is a different one",
        "a package here looks like one you named, but is a different one",
    ),
    "origin.only_in_untrusted": ReasonText(
        "{subject} came from content the agent read, not from you",
        "a key detail came from content the agent read, not from you",
    ),
    "origin.owner_config": None,
    "origin.recipient_mail_domain": None,
    "origin.request_named": None,
    "origin.self_recipient": None,
    "origin.sibling_only": None,
    "origin.sibling_value_untrusted": ReasonText(
        "it uses a value from content the agent read, not from you",
        "it uses a value from content the agent read, not from you",
    ),
    "origin.switched_provider": ReasonText(
        "{subject} now serves a tool another provider served earlier",
        "this tool came from another provider earlier in the session",
    ),
    "origin.written_content_untrusted": ReasonText(
        "the file it runs names {subject}, which came from content the agent read",
        "the file it runs uses details from content the agent read",
    ),
    "path.browser_profile": ReasonText(
        "{subject} holds browser logins and cookies",
        "it involves a browser's saved logins and cookies",
    ),
    "path.credential_bearing_config": ReasonText(
        "{subject} is a settings file that can hold passwords or keys",
        "it involves a settings file that can hold passwords or keys",
    ),
    "path.credential_store": ReasonText(
        "{subject} holds passwords or keys",
        "it involves a file that holds passwords or keys",
    ),
    "path.pii_store": ReasonText(
        "{subject} holds personal mail, messages or contacts",
        "it involves personal mail, messages or contacts",
    ),
    "priv.group_switch": ReasonText(
        "it switches to a group with admin-level access",
        "it switches to a group with admin-level access",
    ),
    "priv.preload": ReasonText(
        "it injects code into other programs as they start",
        "it injects code into other programs as they start",
    ),
    "priv.setuid": ReasonText(
        "it gives a program lasting admin rights",
        "it gives a program lasting admin rights",
    ),
    "priv.shadowing": ReasonText(
        "it swaps in its own version of a system tool",
        "it swaps in its own version of a system tool",
    ),
    "priv.sudo": ReasonText(
        "it runs with administrator (root) rights",
        "it runs with administrator (root) rights",
    ),
    "relief.credential_grant": None,
    "relief.credential_own_service": None,
    "relief.destination_grant": None,
    "relief.file_grant": None,
    "relief.known_good_destination": None,
    "relief.known_good_provider": None,
    "relief.owner_config_destination": None,
    "relief.provider_grant": None,
    "relief.repo_grant": None,
    "relief.request_named_destination": None,
    "relief.request_named_service": None,
    "relief.tool_grant": None,
    "remote.account_change": ReasonText(
        "it changes an account or payment setting on {subject}",
        "it changes an account or payment setting",
    ),
    "remote.delete": ReasonText(
        "it deletes something on {subject}",
        "it deletes something on a remote service",
    ),
    "remote.force_push": ReasonText(
        "it rewrites shared code history (a force push)",
        "it rewrites shared code history (a force push)",
    ),
    "remote.grant": ReasonText(
        "it gives out a role, key or secret on {subject}",
        "it gives out a role, key or secret on a remote service",
    ),
    "remote.payment": ReasonText(
        "it makes a payment to {subject}",
        "it makes a payment",
    ),
    "remote.privileged_role_not_named": ReasonText(
        "it grants a powerful role you did not ask for",
        "it grants a powerful role you did not ask for",
    ),
    "reputation.known_bad_channel": ReasonText(
        "{subject} is on Sentrook's list of known bad channels",
        "a channel here is on Sentrook's known-bad list",
    ),
    "reputation.known_bad_host": ReasonText(
        "{subject} is on Sentrook's list of known bad sites",
        "a site here is on Sentrook's known-bad list",
    ),
    "reputation.known_bad_mcp_server": ReasonText(
        "{subject} is on Sentrook's list of known bad tool servers",
        "a tool server here is on Sentrook's known-bad list",
    ),
    "reputation.known_bad_package": ReasonText(
        "{subject} is on Sentrook's list of known bad packages",
        "a package here is on Sentrook's known-bad list",
    ),
    "reputation.known_bad_plugin": ReasonText(
        "{subject} is on Sentrook's list of known bad plugins",
        "a plugin here is on Sentrook's known-bad list",
    ),
    "reputation.known_bad_recipient": ReasonText(
        "{subject} is on Sentrook's list of known bad recipients",
        "a recipient here is on Sentrook's known-bad list",
    ),
    "reputation.known_bad_repo": ReasonText(
        "{subject} is on Sentrook's list of known bad code repositories",
        "a code repository here is on Sentrook's known-bad list",
    ),
    "reputation.local_host": None,
    "reputation.near_miss_channel": ReasonText(
        "{subject} looks like a copy of a well-known channel",
        "a channel here looks like a copy of a well-known one",
    ),
    "reputation.near_miss_host": ReasonText(
        "{subject} looks like a copy of a well-known site",
        "a site here looks like a copy of a well-known one",
    ),
    "reputation.near_miss_mcp_server": ReasonText(
        "{subject} looks like a copy of a well-known tool server",
        "a tool server here looks like a copy of a well-known one",
    ),
    "reputation.near_miss_package": ReasonText(
        "{subject} looks like a copy of a well-known package",
        "a package here looks like a copy of a well-known one",
    ),
    "reputation.near_miss_plugin": ReasonText(
        "{subject} looks like a copy of a well-known plugin",
        "a plugin here looks like a copy of a well-known one",
    ),
    "reputation.near_miss_recipient": ReasonText(
        "{subject} looks like a copy of a well-known recipient",
        "a recipient here looks like a copy of a well-known one",
    ),
    "reputation.near_miss_repo": ReasonText(
        "{subject} looks like a copy of a well-known code repository",
        "a code repository here looks like a copy of a well-known one",
    ),
    "reputation.self_recipient": None,
    "reputation.switched_provider": ReasonText(
        "{subject} replaced this tool's earlier provider and is new to Sentrook",
        "this tool now comes from a provider new to Sentrook",
    ),
    "reputation.unknown_channel_as_recipient": ReasonText(
        "the channel {subject} is new to Sentrook",
        "a channel it sends to is new to Sentrook",
    ),
    "reputation.unknown_host_as_code_source": ReasonText(
        "{subject} is new to Sentrook as a source of code",
        "where its code comes from is new to Sentrook",
    ),
    "reputation.unknown_host_as_data_destination": ReasonText(
        "{subject} is new to Sentrook as a place to send data",
        "where it sends data is new to Sentrook",
    ),
    "reputation.unknown_in_written_selfmod": ReasonText(
        "what it saves would later contact {subject}, which is new to Sentrook",
        "what it saves would later contact a place new to Sentrook",
    ),
    "reputation.unknown_mcp_server_as_data_destination": ReasonText(
        "the tool server {subject} is new to Sentrook and gets this data",
        "the tool server that gets this data is new to Sentrook",
    ),
    "reputation.unknown_mcp_server_as_tool_provider": ReasonText(
        "the tool server {subject} is new to Sentrook",
        "the tool server is new to Sentrook",
    ),
    "reputation.unknown_package_as_code_source": ReasonText(
        "the package {subject} is new to Sentrook",
        "a package it uses is new to Sentrook",
    ),
    "reputation.unknown_plugin_as_code_source": ReasonText(
        "the plugin {subject} is new to Sentrook",
        "a plugin it uses is new to Sentrook",
    ),
    "reputation.unknown_plugin_as_data_destination": ReasonText(
        "the plugin {subject} is new to Sentrook and gets this data",
        "the plugin that gets this data is new to Sentrook",
    ),
    "reputation.unknown_recipient_as_recipient": ReasonText(
        "{subject} is new to Sentrook as a recipient",
        "a recipient is new to Sentrook",
    ),
    "reputation.unknown_repo_as_code_source": ReasonText(
        "{subject} is new to Sentrook, on a site where anyone can publish",
        "the code repository is new to Sentrook",
    ),
    "retry.denied_consequence_carried": ReasonText(
        "it retries an action that was stopped earlier",
        "it retries an action that was stopped earlier",
    ),
    "retry.none": None,
    "retry.same_action": ReasonText(
        "this same action was stopped earlier in this session",
        "this same action was stopped earlier in this session",
    ),
    "retry.same_destination_new_source": ReasonText(
        "it tries other data where a send was stopped earlier",
        "it tries other data where a send was stopped earlier",
    ),
    "retry.same_source_new_destination": ReasonText(
        "it sends data elsewhere after its earlier send was stopped",
        "it sends data elsewhere after its earlier send was stopped",
    ),
    "retry.same_source_only": ReasonText(
        "an action on this data was stopped earlier in this session",
        "an action on this data was stopped earlier in this session",
    ),
    "selfedit.concealment": ReasonText(
        "this save hides what it says or does",
        "this save hides what it says or does",
    ),
    "selfedit.not_grounded": ReasonText(
        "part of this save isn't backed by the conversation",
        "part of this save isn't backed by the conversation",
    ),
    "selfedit.persists_secret": ReasonText(
        "this save stores a secret you didn't ask the agent to keep",
        "this save stores a secret you didn't ask the agent to keep",
    ),
    "selfedit.risky_step": ReasonText(
        "the saved skill tells the agent to run a risky command later",
        "the saved skill tells the agent to run a risky command later",
    ),
    "selfedit.unsupported_owner_claim": ReasonText(
        "this save claims an approval from you that nothing shows",
        "this save claims an approval from you that nothing shows",
    ),
    "selfedit.untrusted_directive": ReasonText(
        "this save turns someone else's words into standing orders",
        "this save turns someone else's words into standing orders",
    ),
    "selfedit.weakens_oversight": ReasonText(
        "this save loosens a rule or check without your say-so",
        "this save loosens a rule or check without your say-so",
    ),
    "selfmod.config": ReasonText(
        "it changes the agent's settings",
        "it changes the agent's settings",
    ),
    "selfmod.hooks": ReasonText(
        "it changes hooks that run automatically",
        "it changes hooks that run automatically",
    ),
    "selfmod.host_approvals": ReasonText(
        "it changes which commands run without asking you",
        "it changes which commands run without asking you",
    ),
    "selfmod.memory": ReasonText(
        "it changes the agent's memory",
        "it changes the agent's memory",
    ),
    "selfmod.plugin": ReasonText(
        "it installs or changes a plugin or skill",
        "it installs or changes a plugin or skill",
    ),
    "selfmod.scheduler": ReasonText(
        "it adds or changes scheduled jobs",
        "it adds or changes scheduled jobs",
    ),
    "selfmod.startup": ReasonText(
        "it changes files that run at startup",
        "it changes files that run at startup",
    ),
    "selfmod.workspace_skill": ReasonText(
        "it changes a skill script in the workspace",
        "it changes a skill script in the workspace",
    ),
    # The card already says where the call sends; the block category covers it when nothing else does.
    "send.off_host": None,
    "sensitivity.session_holds_sensitive": ReasonText(
        "it sends data from {subject}, which holds sensitive information",
        "it sends data out after the agent read sensitive data",
    ),
    "spawn.hidden_subagent": ReasonText(
        "it starts a helper agent that works out of your sight",
        "it starts a helper agent that works out of your sight",
    ),
    "trigger.heartbeat": ReasonText(
        "this was started by the agent's routine wake-up, not by you",
        "this was started by the agent's routine wake-up, not by you",
    ),
    "trigger.hook": ReasonText(
        "this was started by an automatic hook, not by you",
        "this was started by an automatic hook, not by you",
    ),
    "trigger.owner": None,
    "trigger.scheduled": ReasonText(
        "this was started by a scheduled job, not by you",
        "this was started by a scheduled job, not by you",
    ),
    "trigger.self_edit": None,
    "trigger.sender_other": ReasonText(
        "the request came from someone other than you",
        "the request came from someone other than you",
    ),
    "trigger.subagent": ReasonText(
        "this request came from another agent, not from you",
        "this request came from another agent, not from you",
    ),
    "trigger.system": ReasonText(
        "this was started by the system, not by you",
        "this was started by the system, not by you",
    ),
    "trigger.trusted_allowlist": ReasonText(
        "the request came from a sender you allowed, not from you",
        "the request came from a sender you allowed, not from you",
    ),
    "trigger.unknown_sender": ReasonText(
        "Sentrook could not tell who sent the request",
        "Sentrook could not tell who sent the request",
    ),
}

#: Entity kinds as the card names them, for code families built with a kind suffix.
KIND_WORDS: dict[str, str] = {
    "channel": "channel",
    "host": "site",
    "mcp_server": "tool server",
    "package": "package",
    "plugin": "plugin",
    "recipient": "recipient",
    "repo": "code repository",
}

#: Families built with a kind suffix (`reputation.known_bad_<kind>`), for a kind no exact entry covers.
_FAMILIES: dict[str, ReasonText] = {
    "reputation.known_bad_": ReasonText(
        "{subject} is on Sentrook's list of known bad {kind}s",
        "something here is on Sentrook's known-bad list",
    ),
    "reputation.near_miss_": ReasonText(
        "{subject} looks like a copy of a well-known {kind}",
        "something here looks like a copy of a well-known name",
    ),
}

#: `reputation.unknown_<kind>_as_<role>` by role, for combinations without an exact entry.
_UNKNOWN_ROLES: dict[str, ReasonText] = {
    "_as_code_source": ReasonText(
        "{subject} is new to Sentrook as a source of code",
        "where its code comes from is new to Sentrook",
    ),
    "_as_data_destination": ReasonText(
        "{subject} is new to Sentrook as a place to send data",
        "where it sends data is new to Sentrook",
    ),
    "_as_data_source": ReasonText(
        "{subject} is new to Sentrook as a source of data",
        "where its data comes from is new to Sentrook",
    ),
    "_as_executable": ReasonText(
        "{subject} is new to Sentrook as a program to run", "a program it runs is new to Sentrook"
    ),
    "_as_recipient": ReasonText(
        "{subject} is new to Sentrook as a recipient", "a recipient is new to Sentrook"
    ),
    "_as_tool_provider": ReasonText(
        "{subject} is new to Sentrook as a tool provider", "the tool's provider is new to Sentrook"
    ),
}
_UNKNOWN = ReasonText("{subject} is new to Sentrook", "something this call uses is new to Sentrook")

#: Text for a code in a domain that says what kind of harm a call does, when no entry or family covers it.
_DOMAINS: dict[str, ReasonText] = {
    "path": ReasonText("it touches {subject}, a sensitive file", "it touches a sensitive file"),
    "exfil": ReasonText(
        "it sends sensitive data to {subject}", "it sends sensitive data off this machine"
    ),
    "send": ReasonText("it sends data to {subject}", "it sends data off this machine"),
    "code": ReasonText(
        "it runs code from {subject}", "it runs code from a source Sentrook does not know"
    ),
    "conceal": ReasonText("it hides what it does", "it hides what it does"),
    "selfmod": ReasonText("it changes the agent's own setup", "it changes the agent's own setup"),
    "guardrail": ReasonText(
        "it interferes with Sentrook or the host's safety settings",
        "it interferes with Sentrook or the host's safety settings",
    ),
    "destroy": ReasonText("it deletes {subject}", "it deletes data in a way that is hard to undo"),
    "priv": ReasonText(
        "it changes privileges on this machine", "it changes privileges on this machine"
    ),
    "remote": ReasonText(
        "it makes a lasting change on {subject}", "it makes a lasting change on a remote service"
    ),
    "artefact": ReasonText("it writes a secret into {subject}", "it writes a secret into a file"),
    "extent": ReasonText(
        "it acts on many files or recipients at once", "it acts on many files or recipients at once"
    ),
}


def reason_text(code: str) -> ReasonText | None:
    """The card text for `code`: its entry, its family's, its domain's, or None."""
    if code in REASONS:
        return REASONS[code]
    if code.startswith("reputation.unknown_"):
        role = code[code.rfind("_as_") :] if "_as_" in code else ""
        return _UNKNOWN_ROLES.get(role, _UNKNOWN)
    for prefix, text in _FAMILIES.items():
        if code.startswith(prefix):
            suffix = code[len(prefix) :]
            kind = KIND_WORDS.get(suffix, suffix.replace("_", " "))
            return ReasonText(text.subject.replace("{kind}", kind), text.plain)
    return _DOMAINS.get(code.split(".", 1)[0])
