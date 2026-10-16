"""Signal registry (skeleton 4.1): every leaf signal, its tier, polarity and merge rule; and the
reason-code registry, a finite list of `domain.detail` codes with a template for the review card.

Convergence only accepts contributions to registered signals. Unknown reason codes are tolerated (a
probe may add one before the registry catches up) and render with a generic template.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


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

#: Reason codes → card template. `{subject}` is the entity display (plugin-resolved); `{tool}` the tool.
REASONS: dict[str, str] = {
    # call (Jev)
    "call.not_supported_by_request": "The call does not follow from what you asked for.",
    "jev.concealment": "The call hides what it does.",
    "jev.sensitivity": "The call touches sensitive data.",
    "jev.reach": "The call's effects reach beyond the workspace.",
    "jev.irreversibility": "The call cannot easily be undone.",
    "jev.self_modification": "The call changes the agent's own setup.",
    "jev.confidence_mean": "The model's answers were uncertain.",
    # exposure
    "exposure.instructions": "Recent content contained instructions aimed at the agent.",
    "exposure.task_change": "Recent content tried to change the agent's task or permissions.",
    "exposure.authority": "Recent content claimed approval or authority it does not have.",
    "exposure.session_tainted": "Earlier in this session the agent read content carrying instructions aimed at it.",
    # origin (context)
    "origin.only_in_untrusted": "{subject} appeared only in content the agent read, not in your request.",
    "origin.written_content_untrusted": "The file being run contains {subject}, which came from content the agent read.",
    "origin.agent_generated": "{subject} was chosen by the agent; you did not name it.",
    "origin.agent_created_visible": "{subject} was created by the agent earlier in this session.",
    "origin.agent_created_dirty_lineage": "{subject} was created by the agent from content it read.",
    "origin.request_named": "You named {subject} in your request.",
    "origin.granted": "A grant covers {subject}.",
    # trigger
    "trigger.owner": "The request came from you.",
    "trigger.scheduled": "This is a scheduled run.",
    "trigger.heartbeat": "This is a heartbeat run.",
    "trigger.subagent": "This request came from another agent.",
    "trigger.hook": "This request came from a hook.",
    "trigger.system": "This request came from the system.",
    "trigger.trusted_allowlist": "The sender is on your trusted list.",
    "trigger.unknown_sender": "The sender could not be identified.",
    "trigger.sender_other": "The request came from someone other than you.",
    # retry
    "retry.none": "No earlier denial matches this action.",
    "retry.same_action": "You denied this same action earlier in this session.",
    "retry.same_source_new_destination": "You denied sending this data earlier; the agent is trying another destination.",
    "retry.same_destination_new_source": "You denied a send to {subject} earlier; the agent is trying other data.",
    "retry.same_source_only": "You denied an action on this data earlier; the agent is reading it again.",
    "retry.denied_consequence_carried": "The consequences of the action you denied earlier carry over to this retry.",
    # session
    "sensitivity.session_holds_sensitive": "The agent read sensitive data earlier in this session and this call sends data out.",
    # reputation (oracle)
    "reputation.local_host": "{subject} is this machine.",
    "reputation.unknown_host_as_data_destination": "We have no reputation data for {subject}, which receives data here.",
    "reputation.unknown_host_as_code_source": "We have no reputation data for {subject}, which supplies code to run here.",
    "reputation.unknown_recipient_as_recipient": "We have no record of {subject}.",
    "reputation.unknown_package_as_code_source": "We have no reputation data for the package {subject}.",
    "reputation.unknown_plugin_as_code_source": "We have no reputation data for the plugin {subject}.",
    "reputation.unknown_mcp_server_as_tool_provider": "We have no reputation data for the tool server {subject}.",
    "reputation.known_bad_host": "{subject} is a known-bad host.",
    "reputation.known_bad_recipient": "{subject} is a known-bad recipient.",
    "reputation.known_bad_package": "{subject} is a known-bad package.",
    "reputation.known_bad_plugin": "{subject} is a known-bad plugin.",
    "reputation.known_bad_mcp_server": "{subject} is a known-bad tool server.",
    # coverage
    "coverage.unknown_entities": "Some entities in this call are unknown to us.",
    "coverage.oracle_unavailable": "Reputation data was unavailable.",
    "coverage.unknown_sender": "The sender could not be identified.",
    "coverage.trigger_unknown": "We could not tell what started this run.",
    "coverage.context": "Part of the session context was missing or truncated.",
    "coverage.probe_failed": "One of the analysis steps failed.",
    # agreement
    "agreement.consequence_split": "The rule-based and model-based assessments of this call's consequences disagree.",
    "agreement.suspicion_split": "The rule-based and model-based assessments of this call's intent disagree.",
    # relief
    "relief.destination_grant": "A grant covers {subject}.",
    "relief.file_grant": "A grant covers access to {subject}.",
    "relief.request_named_destination": "You named {subject} as the destination in your request.",
    # AIRA: consequence classes (C1 to C10) and extent
    "path.credential_store": "{subject} is a credential store.",
    "path.credential_bearing_config": "{subject} is configuration that carries credentials.",
    "path.browser_profile": "{subject} is a browser profile (cookies, logins).",
    "path.pii_store": "{subject} holds personal data.",
    "exfil.exec_egress": "The command sends local data to {subject}.",
    "exfil.message_send": "The message carries sensitive data to {subject}.",
    "exfil.web_post": "The request posts local data to {subject}.",
    "exfil.raw_socket": "The command opens a raw network connection to {subject}.",
    "exfil.placeholder_in_argv": "A secret appears in the call's arguments.",
    "exfil.attachment": "The message attaches {subject}, a sensitive file.",
    "exfil.session_holds_sensitive": "The agent read sensitive data earlier in this session and this call sends data out.",
    "send.off_host": "The call sends data to {subject}.",
    "code.fetch_to_shell": "The command fetches content from {subject} and runs it.",
    "code.decode_to_shell": "The command decodes a hidden payload and runs it.",
    "code.install_from_url": "The command installs software from {subject}.",
    "code.package_install": "The command installs the package {subject}.",
    "code.run_written_file": "The command runs a file the agent wrote earlier from fetched content.",
    "selfmod.memory": "The call changes the agent's memory.",
    "selfmod.config": "The call changes the agent's configuration.",
    "selfmod.scheduler": "The call changes scheduled jobs.",
    "selfmod.plugin": "The call installs or changes a plugin or skill.",
    "selfmod.startup": "The call changes files that run at startup.",
    "selfmod.hooks": "The call changes hooks.",
    "guardrail.plugin_disable": "The call disables or removes the Sentrook plugin. Make this change yourself through Sentrook's own controls.",
    "guardrail.state_dir_write": "The call writes into Sentrook's state directory. Make this change yourself through Sentrook's own controls.",
    "guardrail.config_entry": "The call edits the Sentrook configuration entry. Make this change yourself through Sentrook's own controls.",
    "guardrail.gateway_stop": "The call stops the agent gateway. Make this change yourself.",
    "guardrail.host_approvals": "The call changes the host's own approval or allowlist settings.",
    "guardrail.log_tamper": "The call truncates or removes the operator log.",
    "destroy.outside_scratch": "The command deletes {subject}, outside the workspace and scratch space.",
    "destroy.workspace_wide": "The command deletes the whole workspace or a large part of it.",
    "destroy.sql": "The command runs destructive SQL.",
    "priv.sudo": "The command runs with elevated privileges.",
    "priv.setuid": "The command sets a setuid bit or capability.",
    "priv.preload": "The command injects a library into other programs.",
    "priv.shadowing": "The command shadows a system utility.",
    "remote.delete": "The command deletes a remote resource on {subject}.",
    "remote.force_push": "The command force-pushes, rewriting shared history.",
    "remote.payment": "The call makes a payment to {subject}.",
    "remote.account_change": "The call changes an account or payment setting.",
    "artefact.placeholder_in_write": "The call writes a secret into {subject}.",
    "artefact.sensitive_basename_committed": "The call commits a sensitive file ({subject}).",
    "artefact.push_with_secret": "The push includes a commit that carries a secret.",
    "extent.recursive": "The command acts recursively over a directory tree.",
    "extent.wildcard": "The command acts on everything a wildcard matches.",
    "extent.bulk_recipients": "The message goes to many recipients at once.",
    "conceal.encoded_payload": "The command hides its payload behind encoding before running it.",
    "conceal.obfuscated_command": "The command is written to hide what it runs.",
    "conceal.output_suppressed": "The command hides its own output and errors.",
    "conceal.command_in_url": "The request hides a shell command inside a URL parameter.",
    "code.param_injection": "The request sends a shell command to a local service through a URL parameter.",
    "code.registry_redirect": "The call points the package manager at {subject}; later installs would come from there.",
    "code.lookalike_installer": "{subject} mimics a well-known installer host; the code being run comes from a look-alike.",
    "selfmod.host_approvals": "The call changes the host's own approval or allowlist settings.",
    "reputation.unknown_channel_as_recipient": "We have no record of the channel {subject}.",
    # floors
    "floor.guardrail_tampering": "This call tampers with the agent's guardrails. Make this change yourself through Sentrook's own controls.",
    "floor.known_bad_entity": "{subject} is known to be malicious.",
    "floor.untrusted_code_execution": "This call runs code from an untrusted source.",
}

GENERIC_TEMPLATE = "{code}"


def template_for(code: str) -> str:
    if code in REASONS:
        return REASONS[code]
    domain = code.split(".", 1)[0]
    return {
        "path": "The call touches {subject}, a sensitive location.",
        "exfil": "The call sends sensitive data to {subject}.",
        "send": "The call sends data to {subject}.",
        "code": "The call runs code from {subject}.",
        "selfmod": "The call changes the agent's own setup.",
        "guardrail": "The call tampers with the agent's guardrails.",
        "destroy": "The call destroys data outside scratch space.",
        "priv": "The call changes privileges on this machine.",
        "remote": "The call makes an irreversible change on a remote service.",
        "artefact": "The call writes a secret into a file.",
        "extent": "The call acts on many files or recipients at once.",
    }.get(domain, GENERIC_TEMPLATE)
