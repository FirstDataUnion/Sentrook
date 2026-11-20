/*
 * Sentrook dashboard view (read-only). The same file ships in the OpenClaw plugin (dashboardView.js, drawn in a
 * Control UI tab) and the Hermes plugin (dashboard/view.js, a Hermes dashboard tab); a test keeps the two copies
 * identical. It draws the model the plugin builds from its traffic log. All text goes in through textContent,
 * never as HTML. No network access of its own: OpenClaw embeds the model in the page, Hermes fetches it with the
 * dashboard SDK from the plugin's own API. Changes are made with the plugin's commands, which the page names.
 */
(function () {
  "use strict";

  var TIER_INFO = {
    suspicion: {
      label: "Suspicion",
      help: "How much the call looks like it serves a goal the owner did not set. Higher is worse.",
      combine: "Any one signal can raise it: each adds to what the others leave.",
      worse: "high",
    },
    consequence: {
      label: "Consequence",
      help: "The worst harm if the call runs. Higher is worse.",
      combine: "The largest of sensitivity × reach, irreversibility × reach, and self-modification.",
      worse: "high",
    },
    confidence: {
      label: "Confidence",
      help: "How much to trust the other two scores. Higher is better; low confidence adds risk on its own.",
      combine: "The lowest of agreement, coverage and model certainty.",
      worse: "low",
    },
  };

  /** Each signal: its label and what a high value means. */
  var LEAF_INFO = {
    misalignment: ["Misalignment", "How far the call strays from what the owner asked for in this turn. High: the call does something the request did not ask for."],
    concealment: ["Concealment", "Whether the call hides or disguises what it does, such as encoded commands or misleading names. High: it looks like it is hiding something."],
    overreach: ["Overreach", "Whether the call acts on more than the request covers, judged against what the agent read. High: it goes wider than needed."],
    distrust: ["Distrust", "How little the destination or target is trusted: unknown, new or look-alike hosts and recipients score high; ones you named or granted score low."],
    request_origin: ["Request origin", "Whether the request came from someone other than the owner, such as a scheduled run, another user or a webhook. High: not the owner's own message."],
    retry_after_denial: ["Retry after denial", "Whether the agent is trying again something that was denied or blocked earlier in the session. High: it looks like a retry."],
    untrusted_origin: ["Untrusted origin", "Whether part of the call (a host, a path, a command) came from content the agent read rather than from the owner. Counts only together with exposure."],
    exposure: ["Exposure", "Whether content the agent read for this call carried instructions aimed at the agent. High: possible prompt injection now."],
    session_exposure: ["Session exposure", "Whether content read earlier in this session carried instructions aimed at the agent. High: the session may have been steered."],
    sensitivity: ["Sensitivity", "How sensitive the data or resource the call touches is: credentials and private keys score highest."],
    reach: ["Reach", "How far the effect goes: staying on this machine scores low, sending to the internet or other people scores high."],
    irreversibility: ["Irreversibility", "How hard the effect is to undo: deleting, sending and publishing score high; reading scores low."],
    self_modification: ["Self-modification", "Whether the call changes the agent's own skills, memory, config or plugins. High: the agent is changing itself."],
    agreement: ["Agreement", "How far the scanner's separate checks agree with each other. Low: they disagree, so the result is less certain."],
    coverage: ["Coverage", "How much of the call the checks could actually see and judge. Low: parts were cut, missing or failed."],
    model_certainty: ["Model certainty", "How sure the model-based check was of its own answer. Low: the model was unsure."],
  };

  var TAINT = ["untrusted_origin", "exposure", "session_exposure"];

  var HINTS = {
    risk: "Overall risk from 0 to 100: consequence × the larger of suspicion and uncertainty (uncertainty grows as confidence falls). A floor can raise it; a grant can lower a signal.",
    meter: "Where this risk sits against the plugin's lines: below the review line the call runs, from the review line you are asked, from the block line it is blocked.",
    formula: "How the three scores combine. Every score here is from 0 to 100.",
    action: "What the plugin did with the call.",
    review: "How the approval prompt was answered, if there was one.",
    id: "The scan's id. The why command with this id shows the same scan as text, with any grant that would allow it next time.",
    time: "When the call was scanned, in this browser's time zone.",
    session: "The session the call ran in. A grant can be bound to this session with --session and this ref.",
    step: "Which tool call in the session this was.",
    mode: "enforce: the plugin acts on the result. observe: it only scores and logs.",
    entity: "Something the call touches (a host, file, channel or tool), as the scanner names it in its reasons.",
    floor: "A scanner floor: a rule for a known dangerous pattern that sets a minimum risk whatever the scores say. Grants and snoozes never lower a floor.",
    relief: "A grant (or a destination you named in your request) that lowered a signal, so the call scored lower.",
    enforced: "The scanner requires this outcome: the plugin must at least ask (review) or block, whatever its own lines.",
    ceiling: "You were in the chat and nothing points to an attack, so the plugin asks you at most and never blocks on the score alone.",
    reason: "The scanner's reason code and, where it has one, the reason in plain words.",
    other: "Reasons not tied to one signal: floors, relief, and gaps in what the scan could check.",
    timeline: "The scans shown below, oldest on the left. Colour shows what happened; height shows the risk. Click one to open it.",
    signals: "The signals the scanner combined into this score. Hover a signal for what it measures.",
    na: "The scanner did not assess this signal for this call (not the same as 0).",
  };

  var FLAG_HINTS = {
    snoozed: ["snoozed", "A snooze was on, so this review was allowed without asking."],
    relaxed: ["snooze asked instead", "A snooze turned a block with no clear attack signal into a question."],
    skill_review: ["background save", "A save to skills or memory made by the host's own background review."],
    self_edit: ["self-edit", "The agent changed its own skills, memory or config."],
  };

  var BUCKETS = {
    blocked: ["Blocked", "Blocked: the call did not run."],
    review: ["Review", "Asked for approval, or held for you."],
    observed: ["Observed", "Observe mode: would have been reviewed or blocked, but ran."],
    allowed: ["Allowed", "Allowed: the call ran."],
    scan_error: ["Scan error", "The scan failed; the plugin applied its scan-error setting."],
  };

  /** The Sentrook mark: the path from brand/sentrook-mark.svg (a 512 square), drawn in the text colour. */
  var MARK_PATH = "m44.8 26c-.2 11.4 .3 22.2 .4 33.4 .4 5.3 .4 11 .8 16.3 .3 6.9 1 13.4 1.3 20.2 .7 4.5 .6 9.7 1.4 14 .3 5.1 1 9.7 1.5 14.6 .7 4.4 1 9.1 1.9 13.4 .3 4.3 1.2 8.1 1.7 12.3 .7 3 1 6.3 1.6 9.4 .7 3.7 1.4 7.4 2.1 11 .7 3.6 1.4 7.3 2.3 10.7 .6 3.6 1.4 6.9 2.3 10.2 .6 3.2 1.3 6.4 2.3 9.2 .6 3.1 1.3 6 2.3 8.8 .5 2.9 1.4 5.5 2.3 8.1 .5 2.7 1.5 4.9 2.1 7.5 .8 2.4 1.6 4.8 2.3 7.3 .8 2.2 1.6 4.5 2.3 6.9 .9 1.7 1.2 4.2 2.3 5.8 .4 2.4 1.5 4.1 2.1 6.3 .9 2 1.7 4.3 2.5 6.5 .9 1.8 1.4 4 2.5 5.6 .5 2.1 1.4 3.8 2.3 5.6 .8 2.3 1.7 4.6 2.9 6.5 .6 2.1 1.6 3.9 2.5 5.7 1 2.5 2.2 5 3.5 7.3 1.1 2.8 2.7 5.1 3.8 7.9 1.4 2.1 2.4 4.5 3.7 6.7 1.1 2.3 2.6 4.3 3.6 6.6 1.5 2 2.5 4.5 4 6.5 1.2 2.3 2.7 4.4 3.9 6.7 1.5 2 2.8 4.3 4.2 6.5 1.5 2 2.8 4.3 4.4 6.2 1.3 2.1 2.8 4.1 4.2 6.1 1.4 1.8 2.7 3.8 4.1 5.6 1.6 1.9 3 4 4.6 5.9 1.5 2.1 3.2 4 4.8 6 1.7 2 3.3 4 5 5.9 1.6 2 3.5 3.7 5 5.8 1.7 1.5 3.1 3.2 4.6 4.8 1.9 2.1 3.9 3.9 5.7 6.1 2 1.8 3.9 3.8 6 5.6 1.7 2.2 4.1 3.7 5.9 5.8 1.9 1.2 3.1 3 5 4.2 1.5 1.8 3.7 3 5.2 4.8 2 1.2 3.4 3 5.4 4.2 1.7 1.6 3.6 3 5.4 4.4 1.9 1.5 3.8 3 5.9 4.3 1.6 1.6 3.8 2.7 5.4 4.2 2.1 1.1 3.7 2.6 5.7 3.8 1.9 1.4 3.8 2.8 6 3.9 .8-1.7 2-2.9 3.1-4.3-2.2-1.5 -4.3-3 -6.6-4.4-2.1-1.5 -4.2-3 -6.3-4.4-1.9-1.6 -4.1-3 -6.1-4.6-2-1.4 -3.8-3 -5.8-4.4-1.9-1.6 -4-3.1 -5.8-4.8-2.1-1.6 -4-3.4 -6.1-5-1.8-1.6 -3.6-3.2 -5.4-4.8-1.8-1.8 -3.8-3.3 -5.5-5.2-2.4-1.8 -4.3-4.3 -6.6-6.3-2-2.3 -4.5-4.2 -6.3-6.6-1.9-1.7 -3.4-3.7 -5.2-5.5-1.7-2 -3.6-3.9 -5.2-6-1.7-1.7 -3.2-3.6 -4.6-5.5-1.7-1.8 -3.2-3.9 -4.8-5.8-1.6-2 -3.1-4 -4.6-6-1.5-2 -3-4 -4.4-6.1-1.5-1.7 -2.6-3.9 -4.2-5.6-1.1-2.1 -2.6-3.8 -3.7-5.9-1.5-2 -2.8-4.3 -4.2-6.5-1.4-2 -2.5-4.2 -4-6.2-1.1-2.4 -2.6-4.4 -3.7-6.7-1.4-2.1 -2.4-4.4 -3.8-6.5-1-2.5 -2.6-4.5 -3.5-7.1-1.2-1.7 -2-3.8 -3.2-5.6-.7-2.3 -1.8-4.1 -2.9-6-.7-2.4 -1.9-4.1 -2.7-6.3-.9-2.1 -1.9-4 -2.7-6.3-1.1-1.7 -1.6-4.1 -2.7-5.8-.6-2 -1.4-3.9 -2.3-5.6-.5-2.3 -1.6-3.9 -2.1-6.1-.9-1.9 -1.6-3.9 -2.3-6.1-.8-2 -1.7-4.1 -2.3-6.4-.8-2.2 -1.7-4.3 -2.3-6.7-.8-2.1 -1.3-4.5 -2.3-6.5-.5-2.8 -1.4-5.2 -2.3-7.7-.6-2.8 -1.4-5.4 -2.3-7.9-.6-3 -1.4-5.9 -2.3-8.6-.6-3.3 -1.4-6.3 -2.3-9.4-.6-3.4 -1.4-6.8 -2.3-10-.6-3.7 -1.4-7.4 -2.3-10.8-.5-3.9 -1.2-7.6 -2-11.1-.5-3.9 -1.2-7.6 -1.9-11.3-.3-3.7 -1.1-6.8 -2.1-9.8-1-4 -1.6-8.5 -1.9-13.1 .4-2.8 .2-7.4 -.4-10.5-.4-5.5 -1.2-10.7 -1.5-16.2-.5-4.7 -.6-9.8 -1.2-14.5-.1-6.7 -.8-12.9 -.9-19.8-.5-3.9 -.1-8.7 -.6-12.7 .2-7.1 -.3-13.6 -.2-20.7 137.2 0 274.4 0 411.6 0-.1 9.4 -.1 18.8 -.6 27.8 0 7.6 -.7 14.5 -.9 21.9-.4 4.8 -.8 9.8 -1 14.8-.6 3.7 -.5 8.1 -1.3 11.7 0 5.7 -1.6 10.8 -1 16.5-.2 2.4 -.2 5.8 -.6 8.5-.5 3.4 -1.4 6.3 -2.1 9.4-1.1 3 -1.2 6.8 -1.9 10.1-.5 3 -.9 6.2 -1.7 8.9-.4 4 -1.2 7.6 -2.1 11.1-.6 3.8 -1.3 7.4 -2.3 10.9-.5 3.5 -1.3 6.8 -2.3 10-.6 3.2 -1.3 6.3 -2.2 9.2-.7 3 -1.4 5.8 -2.3 8.5-.6 2.8 -1.4 5.4 -2.3 7.9-.5 2.7 -1.6 4.9 -2.1 7.6-.9 2.2 -1.7 4.6 -2.3 7.1-.9 2.1 -1.7 4.3 -2.3 6.6-.9 2.1 -1.7 4.2 -2.3 6.5-.9 1.6 -1.3 3.8 -2.3 5.4-.5 2.4 -1.7 4.2 -2.3 6.5-.9 1.9 -1.8 3.9 -2.5 6-1.1 1.8 -1.6 4.2 -2.7 5.9-.9 2.2 -1.7 4.5 -2.9 6.5-.9 2.5 -2.2 4.6 -3.2 7.1-1.3 1.8 -1.8 4.5 -3.3 6.2-1 2.6 -2.5 4.8 -3.6 7.3-1.4 2 -2.2 4.6 -3.7 6.5-1.1 2.5 -2.6 4.5 -3.8 6.9-1.3 2 -2.5 4.1 -3.7 6.2-1.4 2.1 -2.7 4.2 -4 6.3-1.3 2 -2.7 4 -4 6.1-1.4 1.9 -2.9 3.9 -4.1 6-1.4 1.7 -2.7 3.6 -4 5.4-1.4 2 -3 3.8 -4.4 5.9-1.5 1.9 -3.1 3.8 -4.6 5.8-1.5 1.9 -3.1 3.7 -4.6 5.7-1.6 1.7 -3.1 3.6 -4.8 5.4-1.7 2 -3.5 3.9 -5.2 5.8-1.5 1.8 -3.4 3.3 -4.8 5.2-2.4 2.2 -4.5 4.6 -6.9 6.7-1.8 2.3 -4.4 4 -6.2 6.3-1.8 1.1 -3 2.7 -4.6 4-1.8 1.6 -3.6 3.2 -5.5 4.8-2 1.6 -4 3.3 -6 5-1.9 1.5 -3.8 3.1 -5.9 4.6-1.7 1.5 -3.5 2.8 -5.4 4.1-1.9 1.6 -3.9 3.1 -6 4.4-1.8 1.6 -4 2.6 -5.7 4.2-2.2 1.1 -4 2.7 -6.2 4-.7 .5 1.2 1.3 1.4 2.2 1 .7 1 2.8 2.1 2.1 2-1.4 4.1-2.8 6.3-4.1 1.8-1.5 3.9-2.8 5.8-4.2 2-1.5 4-3 6.1-4.4 1.7-1.5 3.5-2.8 5.4-4.2 1.7-1.5 3.6-2.9 5.4-4.4 1.9-1.6 3.8-3.1 5.7-4.8 2-1.6 4-3.4 6-5.2 1.8-1.7 3.9-3.2 5.4-5.2 2.3-1.3 3.5-3.7 5.7-5 2-2.3 4.4-4.2 6.2-6.7 2.3-1.8 3.9-4.2 6.1-6 1.3-2 3.2-3.5 4.6-5.5 1.7-1.5 3-3.6 4.8-5.2 1.2-2.1 3.1-3.6 4.4-5.6 1.6-1.8 2.9-3.8 4.6-5.6 1.4-2.2 3.2-4.1 4.6-6.3 1.4-1.9 2.9-3.8 4.1-5.9 1.5-1.7 2.7-3.6 4-5.6 1.4-1.9 2.8-3.9 4-6 1.4-2 2.7-4.1 3.9-6.3 1.5-2 2.6-4.2 4-6.3 1.1-2.2 2.4-4.3 3.7-6.4 1.1-2.6 2.8-4.6 3.8-7.3 1.4-1.7 2.1-4 3.3-5.9 1.1-2.8 2.7-5.1 3.8-7.9 1.3-1.8 1.8-4.3 3.1-6.1 .6-2.1 1.8-3.5 2.3-5.6 1.1-1.9 1.9-4 2.7-6.1 .9-1.9 1.8-3.9 2.5-6 1-2 1.8-4 2.5-6.3 1-1.6 1.4-3.8 2.3-5.4 .5-2.3 1.6-4 2.1-6.3 1-1.7 1.3-4.1 2.3-5.8 .5-2.5 1.6-4.4 2.1-6.9 1-2 1.3-4.6 2.3-6.5 .6-2.7 1.5-5.2 2.3-7.7 .5-2.8 1.6-5.1 2.1-7.9 .8-2.8 1.7-5.7 2.3-8.8 .9-2.9 1.7-6 2.3-9.2 1-3.1 1.4-6.9 2.5-10 .6-3.8 1.4-7.5 2.3-11 .3-3.6 1.3-6.5 1.7-10.1 .7-3.1 1.2-6.4 1.6-9.8 .8-2.9 .9-6.4 1.7-9.4 .4-4.6 1.3-8.8 1.7-13.5 .6-3.8 1-7.9 1.4-11.9 .6-4.3 .8-9 1.5-13.2 .2-5.4 .7-10.6 1.2-15.8 .4-7.7 .8-15.3 1.3-22.8 .2-7.7 .3-15.4 .6-22.9 0-5.3 0-10.6 0-15.9-140.8 0 -281.6 0 -422.4 0zm86 10.2c-4.2 .4 -8.8 .3 -13 .7-3.7 .5 -7.8 .6 -11 1.6-3.8 .4 -6.8 1.5 -10.3 2.1-2.4 .9 -5.3 1.3 -7.5 2.3-2.5 .5 -4.4 1.5 -6.9 2.1-2.1 .9 -4.2 1.7 -6.4 2.5-1.3 1 -3.6 1 -5.2 1.7-1.6 1.8 -3 3.7 -4.4 5.6-1.1 2.1 -2 4.5 -2.7 6.9-.7 3.3 -1.6 6.5 -1.7 10.4-.8 5.6 -.7 12.1 -.4 18.2 .3 5.5 .5 11.2 1.2 16.3 .3 4.7 .9 9.2 1.5 13.7 .6 3.5 1.2 6.9 1.7 10.5 .6 3.1 1.2 6.1 1.6 9.4 .8 2.6 1.2 5.7 1.9 8.5 .6 2.2 .7 4.7 1.5 6.7 1.1 2.2 3 3.8 4.6 5.6 1.8 1.6 3.7 3.3 5.8 4.6 1.8 1.2 3.7 2.3 5.8 3.2 3.3 1 7.5 2.2 11.9 1.4 3.7-.2 6.2-1.5 8.6-2.9 2.4-1.4 4.5-3.2 6-5.4 1.4-1.1 2.8-2.1 3-4.2 .7-.9 .9-4 1.8-1.7 .7 2.8 2.3 4.6 3.2 7.1 1.4 1.9 2.2 4.4 3.1 6.7 1.1 2.2 2.2 4.4 3.4 6.5 1.2 1.8 2.4 3.8 3.9 5.4 1.7 2 3.3 3.9 5.4 5.4 1.6 1.6 3.6 2.7 5.5 4 1.9 1 3.9 1.9 6.2 2.5 3.3 1.3 9.4 1.6 12.8 .2 2.3-.3 3.7-1.5 5.6-2.3 2.2-1.6 4.3-3.2 5.8-5.4 1.6-1.6 2.6-3.7 3.8-5.7 .8-2.3 1.9-4.3 2.7-6.6 1.2-1.6 1.5-4.1 2.7-5.7 .6-1.5 1 2.4 1.7 2.7 .5 2.4 1.6 4.1 2.3 6.3 .8 2.2 1.3 4.7 2.1 6.9 .9 2.1 1.7 4.4 2.9 6.3 .9 2.4 2.5 4.3 3.8 6.4 1.7 2 3.1 4.2 5.2 5.9 1.6 1.8 3.6 3.2 5.6 4.6 1.8 1.2 3.7 2.2 5.9 3.1 3.3 1.1 7.4 2.2 11.8 1.5 3.7-.2 6.2-1.5 8.6-3 2-1.1 3.8-2.6 5.2-4.4 2.1-.6 2.4-3.2 4-4.3 1-2.3 3.2-3.2 3.5-6.1 1-2.9 1.7-6.1 1.9-9.8 .8-6.6 .5-15 0-21.7-.3-4.6 -.6-9.1 -1.2-13.4-.1-4.8 -1.1-8.8 -1.3-13.5-.7-3.2 -.8-7 -1.7-10-.4-3.8 -1-7.4 -2-10.7-.5-3.2 -1.4-6 -2.1-9-.9-2.3 -1.4-5 -2.5-7.1-.6-2.4 -1.7-4.3 -2.3-6.6-1-1.9 -1.6-4.2 -2.7-5.9-.7-2.2 -1.9-3.8 -2.8-5.8-1.2-2.1 -2.5-4.2 -3.7-6.3-1.4-1.8 -2.7-3.7 -4-5.6-1.7-2 -3.3-4 -5-5.9-1.8-1.6 -3.6-3.3 -5.6-4.8-1.9-1.6 -4.1-2.9 -6.1-4.3-2.3-1.2 -4.3-2.7 -6.7-3.8-1.8-1.2 -4.1-2 -6-3.1-2-.7 -3.8-1.5 -5.6-2.3-2.5-.7 -4.7-1.8 -7.3-2.3-2.4-.9 -5.2-1.4 -7.6-2.3-3.3-.6 -6.5-1.4 -9.6-2.3-3.3-.4 -7.9-.7 -11-.6-4.4-.7 -9.9-.2 -14.4-.7-1.6 .2 -3.2 .2 -4.8 0zm245.6 0c-4.7 .5 -10.4 0 -15 .7-2.4-.1 -6.3 .2 -9.2 .4-3.2 .9 -6.8 1.4 -9.8 2.5-3.1 .4 -5.9 1.3 -8.6 2.3-2.4 .5 -4.8 1.3 -6.8 2.3-2.7 .6 -4.6 2 -7.1 2.7-2 1.1 -4 2.1 -6.1 3.1-2 1.3 -4.1 2.5 -6.2 3.8-2 1.3 -4 2.7 -5.9 4.1-1.9 1.9 -4.2 3.4 -5.8 5.5-1.7 1.5 -3 3.5 -4.6 5.2-1.3 2.1 -3 4 -4.2 6.2-1.5 2 -2.6 4.5 -4 6.5-1 2.4 -2.2 4.6 -3.1 7.1-1 2 -1.8 4 -2.5 6.3-.9 2 -1.7 4 -2.3 6.2-.9 2.4 -1.6 4.9 -2.3 7.5-.9 3.4 -1.8 6.6 -2.3 10.3-.9 2.8 -1 6.5 -1.9 9.4-.4 4.9 -1.4 9.4 -1.6 14.6-.8 3.9 -.7 8.8 -1.5 12.7-.4 7.5 -1.1 14.8 -.8 22.9 .1 4.7 .3 9.4 1.6 13 .3 2.7 1.1 5 2.7 6.3 1.2 1.9 2.7 3.4 3.8 5.4 1.2 1.4 2.9 2.2 4 3.8 2 1.1 3.5 2.7 6 3.3 2.8 1.6 8.3 2.2 12.3 1.2 2.7-.2 4.8-1.1 6.7-2 2.3-.9 4.1-2.3 6.1-3.6 2.1-1.6 3.9-3.4 5.8-5.2 1.1-1.8 2.7-3.1 3.8-5 1.4-2.1 2.8-4.2 3.7-6.7 1.1-1.9 1.9-4 2.5-6.3 1.1-1.9 1.1-4.8 2.3-6.6 .7-2.5 1.9-4.4 2.5-6.9 .5-2.4 1.3-1.2 1.9 .4 .8 2.3 1.8 4.5 2.9 6.5 .7 2.5 1.9 4.5 3 6.6 1.5 2.2 2.9 4.5 5 6.1 1.6 1.7 3.6 3 6 4 2.9 1.5 6.8 2 11.5 1.8 2.6-.5 5.2-.9 7.1-2 2.2-.5 3.5-2 5.4-2.8 1.8-1.5 3.9-2.7 5.4-4.6 1.9-1.5 3.4-3.4 4.8-5.4 1.6-1.8 2.7-4 4-6 .9-2.2 2.1-4.1 2.7-6.5 1-2.3 2.4-4.3 3.4-6.7 1-1.6 1.8-3.5 2.5-5.6 1.2 1.1 1.1 3.5 2.3 4.8 .9 1.5 2.5 2.2 3.3 3.7 1.9 1.7 3.6 3.4 6.1 4.4 2.9 1.8 6.7 2.7 11.6 2.5 3.5-.1 6-1.2 8.8-2.1 2.1-1.2 4.3-2.4 6.3-3.7 1.9-1.7 4-3.2 5.6-5.2 1.3-1.6 3-2.8 3.6-5 .2-3.4 1.3-5.9 1.6-9.2 .8-2.8 1.3-6 1.9-9 .7-3.4 1-7.2 1.9-10.4 .4-4 1.1-7.7 1.6-11.5 .2-5.4 1.2-9.9 1.3-15.3 .6-4.9 .6-10.4 .8-15.6 0-6.5 -.4-12.6 -1.4-18.2-.7-2.7 -1.3-5.5 -2.3-7.9-1.1-2 -2.1-4.1 -3.8-5.6-.9-1.4 -1.7-3.1 -3.9-3.2-2.5-.3 -4.1-1.5 -6.3-2-2-.9 -4.1-1.6 -6.3-2.3-2.7-.9 -5.2-1.9 -8.1-2.5-2.6-1 -5.7-1.4 -8.4-2.3-3.9-.7 -7.8-1.4 -11.6-2.1-5.9-.3 -11.2-1.1 -17.6-.9-1.3-.2 -3.3 .1 -4.8-.2zm-156.3 94.4c.6 .1 .4 .9 0 0zm71.6 0c0 .6 0 .1 0 0zm-220.4 34.2c.6 4 1.1 8 1.9 11.7 .6 3.5 1.5 6.7 2.3 10 .7 2.8 1.4 5.6 2.5 8.1 .5 2.7 1.6 4.9 2.3 7.6 .8 2.1 1.6 4.3 2.3 6.6 .8 1.9 1.2 4.2 2.3 5.9 .4 2.6 1.7 4.4 2.3 6.9 .8 1.9 1.6 3.9 2.2 6 1.1 1.8 1.5 4.2 2.6 5.9 .4 2.2 1.5 3.7 2 5.8 1.1 1.8 1.6 4 2.8 5.6 .9 2.7 2.2 5 3.5 7.3 .9 2 2 3.7 2.9 5.7 1.4 2.1 2.5 4.5 4 6.4 1.1 2.3 2.6 4.2 3.7 6.3 .9 1.8 2 3.3 3.6 4.4 1.5 1.8 3.6 3.1 5.4 4.6 3 1.5 5.9 3.1 10.9 2.7 2.3-.7 4.5-1.4 5.8-3.1 1.9-1 2.7-3.1 4-4.6 1-2.5 2.2-4.8 2.7-7.7 .7-2.1 .9-4.9 2.1-6.5 .3-2.9 1.2 .2 1.9 1 .8 2.6 2.4 4.4 3.3 6.9 1.1 2.2 2 4.7 3.3 6.7 1 2.4 2.6 4.3 3.8 6.5 1.4 1.6 2.5 3.6 4.2 5 1.2 2 3.2 3.2 5 4.8 1.6 1.4 3.9 2.2 5.8 3.3 2.7 .7 6.4 .9 9 0 2.1-1.2 4.2-2.3 5.4-4.4 1.5-1.5 2.6-3.5 3.4-5.8 1.1-2.6 1.9-5.4 2.3-8.8 .4-3.1 .8-6.4 1.6-9.2 0-3.6 .9-1.1 1.7 .2 1 2.5 2.4 4.6 3.5 6.9 1.2 1.7 1.6 4 2.8 5.7 1 2.5 2.2 4.7 3.5 6.9 1.3 2 2.6 4 4.2 5.8 1.5 1.9 2.9 3.9 5 5.2 1.5 1.7 3.5 2.8 5.4 4 2.6 1 5.1 2 9 1.7 2.3-.8 4.6-1.5 5.8-3.2 1.9-1 2.7-3 4-4.6 .9-2.2 2-4.2 2.5-6.9 .9-1.5 .2-4.5 .6-6-.4-3.9 -.1-8.5 -1-11.9-.3-4.1 -1.2-7.7 -1.7-11.7-.7-3 -1.3-6.1 -1.9-9.2-.9-2.9 -1.2-6.6 -2.3-9.4-.5-3.1 -1.3-6 -2.3-8.7-.5-2.8 -1.5-5.3 -2.2-8-1-2.1 -1.5-4.6 -2.6-6.6-3.1 .3 -6.8 1.3 -10.4 .6-1.3 .1 -3.3-.5 -5.2-.9-2-.7 -4.3-1.2 -5.8-2.5-2.8-.9 -4.7-2.7 -6.9-4.1-1.7-1.2 -2.9-2.9 -4.6-4-1.3-1.8 -3-3.3 -4.2-5.2-1.6-1.9 -2.8-4.1 -4.2-6.3-1-2.1 -2.1-4.2 -2.9-6.4-.7-1.9 -1.5-3.6 -1.9-5.7-1.4 1.3 -1.8 3.7 -3.3 5-.9 2 -2.6 3.3 -3.8 5-1.7 1.1 -2.8 2.8 -4.8 3.6-1.4 1.5 -4 1.9 -5.8 3.1-3.5 .8 -7 1.6 -11.5 1.3-1.2-.4 -3.5-.6 -5.4-1.1-2-.8 -4.3-1.2 -5.9-2.5-2.7-1 -4.6-2.7 -6.9-4.2-1.6-1.1 -2.8-2.8 -4.5-3.9-1.3-1.9 -3-3.3 -4.2-5.2-1.6-1.9 -2.9-4.2 -4.2-6.3-1-2.1 -2.1-4.2 -2.9-6.5-.8-1.4 -1-3.3 -1.9-4.6-1.2 1.9 -3.1 3.1 -4.6 4.6-2 1.1 -3.4 2.6 -5.8 3.2-2.2 1.2 -4.8 1.9 -8 2-2.4 .7 -5.8 0 -7.3 0-2.5-.5 -4.9-1.3 -7.3-2-2-1.2 -4.1-2.1 -6-3.4-2-1.5 -4.3-2.8 -5.9-4.8-.4 0 -.4-.7 -1-.6zm369 0c-1.7 2 -3.8 3.6 -6.1 5-1.8 1.5 -4.1 2.6 -6.4 3.6-2.2 1 -4.9 1.6 -7.5 2.2-1.6 .2 -5.7 .5 -8.4 0-2.4-.5 -5-.8 -6.7-2-2.5-.7 -4-2.2 -6-3.4-1.5-1.4 -3.2-2.6 -4.4-4.4-1 1.8 -1.3 4.3 -2.5 5.9-.7 2.6 -2.2 4.4 -3.1 6.7-1.5 2 -2.7 4.3 -4.4 6-1.1 1.8 -2.6 3.1 -4 4.6-1.8 1.6 -3.5 3.3 -5.6 4.6-1.7 1.3 -3.6 2.4 -5.7 3.3-1.9 1.1 -4.4 1.7 -6.6 2.5-3 .4 -4 .8 -7.8 .7-3.5-.2 -6.7-.8 -9.1-2.1-2.7-.7 -4.4-2.3 -6.5-3.6-1.5-1.4 -3.2-2.6 -4.4-4.4-1.6-1.8 -3-3.9 -4.2-6.2-.8-2.4 -1.5-1 -1.9 1-.9 2 -1.5 4.4 -2.7 6.1-.4 1.9 -1.6 3 -2.3 4.8-1.4 2 -2.6 4.3 -4.3 6-1.1 1.8 -2.7 3.1 -4 4.6-1.8 1.6 -3.5 3.4 -5.6 4.6-1.7 1.4 -3.6 2.4 -5.7 3.4-1.9 1.1 -4.5 1.6 -6.7 2.5-2.9 .3 -3.9 .7 -7.7 .6-2.5 .3 -4.6-1.1 -6.7-.6-.6 2.4 -1.6 4.5 -2.3 7.1-.9 2.2 -1.5 4.8 -2.3 7.3-.9 2.4 -1.3 5.5 -2.2 7.9-.7 3.5 -1.5 6.9 -2.3 10.2-.6 3.7 -1.5 7.2 -2.1 10.9-.6 4.3 -1.5 8.4 -1.9 12.9-.5 3.4 -.3 8 -.6 10.9 .2 2.3 .2 4.7 1.2 6.2 .6 2.4 1.7 4.2 2.7 6.1 1.5 1.8 2.8 3.7 5 4.8 1.9 1.4 6.1 2.3 9 1.2 2.8-.3 4.4-1.7 6.5-2.7 1.8-1.6 3.9-2.9 5.4-4.8 1.6-1.7 3.1-3.4 4.4-5.4 1.5-1.8 2.6-4.1 4-6.1 1-2.2 1.9-4.4 3.1-6.4 .6-3.1 2.6-4.8 3.5-7.5 1.3-1.5 1.8-3.7 3-5.3 .2 4.1 1.6 7 1.6 11.3 .7 2.9 1 6.1 2.3 8.4 .6 2.6 2.1 4.4 3.4 6.4 1.6 1.7 3.1 3.4 5.6 4.2 2.5 1.3 7.7 1.1 9.8-.4 2.5-.6 4-2.1 5.9-3.4 1.9-1.5 3.7-3.2 5.2-5.2 1.6-1.9 3.1-3.8 4.4-6 1.4-2.1 2.7-4.4 3.7-6.9 1-1.6 1.7-3.6 2.5-5.4 1.5-2.1 2.4-4.8 3.8-6.9 .6-2.8 1.2 1 1.9 1.9 .8 2.8 1.2 6 2.2 8.7 1 2.4 2.2 4.6 3.6 6.5 1.6 1.7 3.2 3.4 5.6 4.2 2.5 1.3 7.7 1.1 9.8-.5 2.5-.5 4-2.1 5.9-3.3 1.8-1.3 3.1-3.1 5-4.4 1-2.3 2.3-4.3 3.8-6.2 1.1-2.3 2.6-4.2 3.7-6.5 1.3-1.7 2-4 3.3-5.6 1.1-2.6 2.6-4.7 3.6-7.3 1.1-1.8 1.7-4.2 2.9-5.9 .5-2.1 1.6-3.6 2.1-5.6 1.1-1.7 1.4-4.2 2.5-5.9 .5-2.1 1.3-3.8 2.1-5.6 .6-2.3 1.6-4.2 2.3-6.5 .8-2.1 1.7-4.1 2.3-6.4 .8-1.8 1.4-3.9 2.1-5.9 .8-2.2 1.6-4.5 2.3-6.9 .9-2.2 1.6-4.6 2.3-7.1 .9-2.6 1.7-5.4 2.3-8.3 1-3.5 1.7-7.2 2.3-11.1 .6-2.4 .7-5.2 1.2-7.7zm-293.5 105.8c-.3 2.5 -1.3 4.3 -2 6.3-1.4 2.2 -2.4 4.7 -4.4 6.2-1.3 2 -3.5 3.1 -5.7 4.2-2.6 1.2 -7.7 1.6 -10.4 .2-1.7-.2 -2.8-1.1 -4.2-1.7 1.1 2.3 2.6 4.2 3.8 6.3 1.4 2.1 2.8 4.3 4.2 6.5 1.4 2.1 2.9 4.2 4.1 6.4 1.6 1.9 2.7 4.2 4.2 6.1 1.1 2 2.6 3.6 3.6 5.6 1.3 .9 1.6 2.9 2.9 3.8 1.1 2 2.6 3.7 3.9 5.6 1.5 2 3.1 3.9 4.4 6.1 1.7 1.7 2.8 3.8 4.4 5.6 1.4 1.8 2.8 3.8 4.4 5.4 1.1 2 2.7 3.3 4 5.1 1.9 .5 4.9 1.7 6.8 .4 2.3-.5 3-2.5 4.2-4 .8-2.5 1.3-5.1 1.9-7.7 .7-1.5 1.6 1.3 2.1 2.1 1.6 1.7 2.4 4.1 4 5.8 1.2 2.2 2.8 4.1 4.3 6.1 1.6 1.8 3.4 3.4 5 5.2 2 1.2 3.5 2.8 5.9 3.5 1.8 1 5.7 1.7 7.3 0 2.1-.9 3.1-2.9 3.7-5.2 .8-1 .6-4.1 1.5-4.2 1.4 1.9 3.2 3.4 4.4 5.5 1.4 1.9 2.7 4 4.4 5.8 1.4 2.1 3.4 3.6 5 5.4 2 1.5 3.7 3.1 6.2 4 1.9 1 5.8 1.7 7.4 0 2-.9 3-2.9 3.7-5.2 1.4-3.2 1.2-8.5 .4-12.1-.6-3.8 -1.1-7.7 -1.9-11.3-.3-3.8 -1.1-7.1 -1.4-10.8-.8-3 -1.1-6.5 -1.9-9.4-.5-3.2 -1.4-5.9 -2.1-8.8-.7-1.8 -1.2-3.7 -1.9-5.4-2.9 1.1 -7.6 1 -10.6 0-2.3-1 -4.3-2.1 -6.3-3.4-2-1.6 -4.1-3.2 -5.8-5.2-1.6-1.7 -3.2-3.4 -4.4-5.4-1.5-1.8 -2.7-4 -4-6.1-1.2-2.1 -2.4-4.2 -3.3-6.6-.6-.9 -1.1-3.1 -1.7-3.4-.7 2.8 -1.2 5.8 -2.1 8.4-.8 1.9 -1.5 4 -2.7 5.6-.9 2.2 -2.6 3.6 -3.9 5.4-1.9 1.1 -3.2 2.7 -5.7 3.2-2.6 1.2 -7.8 1.1 -10.2-.3-2.6-.5 -4.3-1.9 -6.3-3.1-2-1.6 -4.1-3.2 -5.8-5.2-1.5-1.7 -3.2-3.4 -4.4-5.4-1.5-1.8 -2.7-4 -3.9-6.1-1.3-2.1 -2.5-4.3 -3.4-6.7-.7-.9 -.8-2.4 -1.7-3.1zm218.1 0c-1 2.2 -1.8 4.7 -3.1 6.7-1.2 2.6 -2.7 4.9 -4.2 7.3-1.4 1.9 -2.7 3.9 -4.3 5.6-1.5 1.9 -3.2 3.6 -5 5-1.7 1.6 -3.7 2.7 -5.7 4-3 1.2 -5.9 2.5 -10.4 2.1-2.4-.5 -4.6-1.2 -6.1-2.5-2-1 -3.3-2.8 -4.8-4.4-1.3-2.2 -2.7-4.2 -3.5-6.9-1.2-2.5 -1.7-5.7 -2.5-8.5-.2-3 -.9 1.3 -1.7 1.6-.6 2.4 -1.9 4 -2.7 6.1-1.3 2 -2.5 4.1 -3.8 6-1.3 1.9 -2.7 3.7 -4.1 5.5-1.6 1.6 -3.2 3.3 -5 4.8-2 1.5 -3.8 3 -6.3 3.9-2.4 1.3 -5.9 2.4 -9.6 1.7-2.3-.2 -3.7-1.3 -3.8 1.5-1 2.6 -1.8 5.5 -2.5 8.5-.8 3 -1.3 6.4 -2.1 9.4-.4 4.1 -1.3 7.7 -1.6 11.9-.8 3.1 -1 6.8 -1.7 10-.5 3.9 -1.5 7.3 -1.3 11.9 .6 2.4 .9 5.1 2.3 6.7 1.2 2.3 3.3 3.6 6.7 3.5 2.7-.4 4.8-1.6 6.7-2.9 1.9-1.4 3.8-2.9 5.2-4.8 2-1.6 3.4-3.8 5-5.8 1.4-2 2.6-4.2 4.4-5.9 .8-.6 1.4-2.4 2.3-2.3 .4 3.1 1.2 5.8 2.7 7.8 1.3 1.9 4.5 3.4 7.5 2.3 2.6-.4 4.2-1.9 6.1-3 1.9-1.6 3.8-3.2 5.4-5.2 1.7-1.6 3-3.5 4.4-5.4 1.3-1.9 2.7-3.7 3.8-5.9 1.2-1.3 1.8-3.4 3.3-4.5 .6 2.5 1.1 5.3 1.9 7.7 1.1 2.1 2.2 4.1 4.8 4.8 2.4 .9 5.6 0 7.1-1.3 1.3-2 3.1-3.5 4.4-5.6 1.6-1.7 2.8-3.7 4.3-5.4 1.4-2.1 3.1-4 4.4-6.1 1.5-1.8 2.8-3.9 4.4-5.6 1.2-2.2 2.9-3.9 4.2-6.1 1-1.7 2.4-3.1 3.3-5 1.5-1.7 2.6-3.8 4-5.6 1.2-2.2 2.7-4.1 3.9-6.3 1.6-2 2.8-4.4 4.4-6.5 1.2-2 2.4-3.9 3.8-5.8 .3-1.2 2.2-3 1.9-3.5-3.1 1.3 -6.1 2.6 -10.9 2.3-2.4-.5 -4.5-1.2 -6-2.6-2.2-1 -3.4-3 -5.1-4.5-1-2.1 -2.4-3.8 -3.1-6.3-.8-1.2 -1-3.1 -1.7-4.4zm-217.8 2.9c.9 .2 -.5 2 0 0zm217.6 0c1 .2 -.4 2 0 0zm-185.7 71c-.6 2.8 -1.7 5.1 -3.1 7.1-1.6 1.5 -3.5 2.7 -6.3 2.9 1.5 1.7 2.8 3.6 4.6 5 1.1 1.8 2.7 3 4 4.6 1.5 1.8 3.3 3.3 4.8 5.2 2 1.8 3.8 4 6 5.7 1.5 1.7 3.4 2.9 5 4.6 2 1.6 3.8 3.4 5.9 5 1.5 1.7 3.7 2.9 5.2 4.8 1.8 1.1 3 3 4.8 4.1 1.8 2.3 4.2 3.9 6 6.1 2 1.2 3.4 3.1 5.2 4.4 1.8 1.5 3.5 3.2 5.5 4.6 1.6 1.6 3.5 3 5.4 4.4 .8 1.1 3.8 2.1 1.5 3.3-1.5 2 -3.3 3.7 -4.8 5.6-1.7 1.9 -3.3 3.8 -5.1 5.7-1.7 1.9 -3.5 3.8 -5.2 5.8-1.6 1.7 -3.2 3.5 -4.8 5.2-1.9 1.7 -3.4 3.9 -5.4 5.5-1.3 2 -3.3 3.3 -4.8 5.2-1.7 1.8 -3.3 3.6 -5 5.4-1.7 1.9 -3.4 3.9 -5 5.8-1.6 2 -3.8 3.5 -5.6 5.3-1.9 1.6 -3.8 3.2 -5.7 4.8-1.7 1.3 -2.9 3.1 -3.5 5.4-1.1 2 -1.7 4.6 -1.9 7.5 .5 2 3.1 2.8 5.4 2.3 2.1-1.4 4.4-2.6 6.3-4.2 2.1-1.4 4-2.9 6.2-4.2 1.9-1.4 4.3-2.4 6.3-3.7 2-1 3.2-2.8 5-4 1.8-1.5 3.7-2.9 5.9-4.2 1.9-1 3.3-2.6 5-3.9 1.8-1.5 3.4-3.2 5.4-4.6 1.7-1.6 3.5-3 5.4-4.4 1.9-1.7 4.1-3.1 6.1-4.8 2-1.4 3.9-2.9 5.8-4.4 1.3-1.2 2.9-2 4-3.3 1-.6 2.5-2.2 2.9-2.1 1.5-1.8 3.6-2.9 5.2-4.6 1.5-.4 2.6-2.4 4-2.3 .7 .5 1.6-.6 2.5 .8 2.2 1.5 4.2 3.2 6.2 4.8 1.1 .9 1.2 1.3 1.9 1.7 1.3 1 2.7 1.9 3.8 3.1 .6 .3 1.9 1.5 2.9 2.1 1.7 1.5 3.6 2.9 5.4 4.2 2 1.7 4.2 3.1 6.1 4.8 2.1 1.4 3.8 3.1 5.8 4.6 1.9 1.5 3.5 3.2 5.5 4.6 1.4 1.4 2.8 2.8 4.8 3.7 2 1.5 4 3 6 4.4 1.6 1.5 3.1 3.1 5 4.2 2.4 1.1 4.5 2.5 6.7 3.8 2 1.5 4.2 2.7 6 4.3 2.1 1.1 3.8 2.6 5.9 3.6 2.7 .5 5.6-.5 5.2-3.8-.5-2.3 -.8-4.8 -2.1-6.4-.6-2.6 -2.1-4.2 -3.9-5.5-1.7-1.6 -3.6-2.9 -5.3-4.6-1.8-1.7 -4-3 -5.4-5.2-1.9-1.7 -3.2-4 -5.2-5.6-1.2-1.8 -2.8-3.2 -4.2-4.8-1.8-2.1 -3.8-3.8 -5.6-5.8-1.7-2 -3.6-3.7 -5.2-5.7-1.8-1.5 -3.2-3.4 -4.8-5-1.7-1.9 -3.4-3.7 -5-5.6-1.6-1.7 -3.2-3.4 -4.6-5.2-1.8-1.8 -3.1-3.9 -5-5.5-.9-1.2 -2.2-2.4 0-3.1 1.7-1.7 3.7-3 5.6-4.6 1.9-1.6 3.7-3.2 5.6-4.8 1.8-1.7 3.8-3.1 5.5-5 1.8-1.2 3-3 4.8-4.2 1.7-2.2 4.2-3.8 6-6 1.7-1.1 3-2.6 4.6-3.8 1.7-1.7 3.9-3.1 5.4-5 2-1.1 3.3-2.9 5-4.2 1.9-1.6 3.6-3.3 5.5-5 1.8-1.9 3.6-3.8 5.4-5.8 1.8-1.6 3.1-3.7 5-5.2 1.5-2.1 3.3-3.7 4.8-5.7-.3-.6 -3.2-.4 -3.8-1.4-2.2-1.1 -3.5-3.2 -4.3-5.7-.7-.7 -.8-4.3 -1.7-2.3-1.2 2.2 -2.7 4.1 -4 6.1-1.5 1.8 -2.9 3.7 -4.6 5.4-1.6 2 -3.6 3.6 -5.6 5.2-2 1.4 -4 2.7 -6.7 3.4-2.1 .9 -5.1 .6 -6.9-.5-1.8-1.3 -3.5-2.9 -4.1-5.4-.6-1.7 -1.3-2.6 -2.1-.6-1.2 2 -2.6 3.8 -4 5.6-1.7 2 -3.4 4.2 -5.4 5.9-1.6 1.7 -3.6 3 -5.4 4.4-2.2 1.1 -4.5 2.1 -7.4 2.5-2.3 0 -3.7-1 -5.4-1.7-1.6 1.9 -3.2 3.7 -4.8 5.6-1.6 1.9 -3.3 3.7 -4.8 5.7-1.7 1.6 -2.9 3.6 -4.6 5.2-.4-2.4 -1.3 1.2 -1.9-.9-1.7-1.4 -2.8-3.5 -4.5-5-1.1-1.7 -2.6-3 -3.8-4.6-1.6-1.8 -3.3-3.6 -4.8-5.6-1.2-1 -2.1 .8 -3.5 .8-2.4 .8 -5.6 .1 -7.4-1-2.6-1 -4.6-2.7 -6.6-4.4-1.9-1.6 -3.6-3.5 -5.3-5.4-1.4-1.8 -2.9-3.6 -4.1-5.6-1.1-.7 -1.2-2.4 -2.3-3-.8 2.8 -2 5.2 -4 6.7-1.7 1.6 -4.8 2.2 -7.7 1.5-2.6-.8 -4.6-2.1 -6.7-3.4-1.9-1.7 -4-3.2 -5.6-5.2-1.6-1.6 -3.1-3.3 -4.4-5.2-1.4-1.8 -2.8-3.7 -4-5.8-.5-.3 -.6-1.2 -1-1.5zm46.3 81.2c.1-.7 -.6 .1 0 0zm36.1 14.4c-.1 .6 .7-.1 0 0zm0 .2c-2.1 .6 -3.4 2.1 -5.8 2.5-1.5-.8 -3.5-2.2 -5-2.3-1.5 1.1 -3 2.3 -4.2 3.8 2.5 1.1 4.7 2.5 7.3 3.5 1.2 1.1 3 1.6 4.2 .2 2.6-1 4.8-2.4 7.3-3.5 1.3-.7 -1.1-1.1 -1.3-2.1-1-.5 -1.7-1.4 -2.5-2.1z";

  var CSS = [
    ".srk{--srk-fg:currentColor;--srk-muted:var(--color-muted-foreground,#7b828c);",
    "--srk-card:var(--color-card,#ffffff);--srk-soft:var(--color-muted,#f2f3f5);--srk-border:var(--color-border,#dfe2e6);",
    "--srk-low:var(--color-success,#2f9e6b);--srk-mid:var(--color-warning,#d9930d);--srk-high:var(--color-destructive,#d64545);",
    "--srk-accent:var(--color-primary,#3b6fd9);--srk-radius:var(--radius,10px);",
    "color:inherit;font:14px/1.45 system-ui,-apple-system,'Segoe UI',sans-serif;max-width:1100px;margin:0 auto;padding:16px;box-sizing:border-box}",
    ".srk *{box-sizing:border-box}",
    // Hosts style code elements page-wide; start ours from nothing.
    ".srk code{all:unset;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}",
    ".srk-standalone{--srk-fg:#1c1e21;--srk-muted:#646b75;--srk-card:#ffffff;--srk-soft:#f2f3f5;--srk-border:#dfe2e6;",
    "--srk-low:#2f9e6b;--srk-mid:#c98a0b;--srk-high:#d64545;--srk-accent:#3b6fd9;--srk-radius:10px;color:var(--srk-fg)}",
    "@media (prefers-color-scheme:dark){.srk-standalone{--srk-fg:#e6e8eb;--srk-muted:#9aa1ab;--srk-card:#1b1e23;",
    "--srk-soft:#252a31;--srk-border:#323840;--srk-low:#4cc38a;--srk-mid:#e5a93a;--srk-high:#f06a6a;--srk-accent:#7aa2ff}}",
    "html.srk-page,html.srk-page body{margin:0;background:#f7f8fa}",
    "@media (prefers-color-scheme:dark){html.srk-page,html.srk-page body{background:#121418}}",
    ".srk h1{font-size:20px;margin:0}.srk h2{font-size:15px;margin:22px 0 8px}",
    ".srk-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px 16px;margin-bottom:6px}",
    ".srk-mark{width:24px;height:24px;flex:none;align-self:center;margin-right:-6px}",
    ".srk-sub{color:var(--srk-muted);font-size:13px}",
    ".srk-hint{cursor:help;text-decoration:underline dotted color-mix(in srgb,currentColor 45%,transparent);text-underline-offset:3px}",
    ".srk-bar-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:12px 0}",
    ".srk-chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--srk-border);border-radius:999px;",
    "padding:2px 10px;font-size:12px;background:var(--srk-card);white-space:nowrap;cursor:help}",
    ".srk-dot{width:8px;height:8px;border-radius:50%;display:inline-block;background:var(--srk-muted)}",
    ".srk-btn{font:inherit;font-size:12px;border:1px solid var(--srk-border);background:var(--srk-card);color:inherit;",
    "border-radius:6px;padding:3px 10px;cursor:pointer}.srk-btn[aria-pressed=true]{border-color:var(--srk-accent);color:var(--srk-accent)}",
    ".srk-spacer{flex:1}",
    // Pending: front and centre.
    ".srk-section{display:flex;align-items:center;gap:8px;font-size:17px;margin:24px 0 10px}",
    ".srk-section-count{font-size:12px;font-weight:600;padding:1px 8px;border-radius:999px;background:var(--srk-soft);color:var(--srk-muted)}",
    ".srk-pending-section .srk-section-count{background:var(--srk-mid);color:var(--srk-card)}",
    ".srk-pending-item{border:2px solid var(--srk-mid);border-radius:var(--srk-radius);background:var(--srk-card);padding:12px 14px;margin:0 0 12px}",
    ".srk-pending-detail{border:1px solid var(--srk-border);border-radius:var(--srk-radius);margin:10px 0 6px;overflow:hidden}",
    ".srk-pending-detail>.srk-detail{border-top:0}",
    ".srk-pending-title{font-weight:600}.srk-pending-meta{color:var(--srk-muted);font-size:12px;margin:2px 0 6px}",
    // Timeline.
    ".srk-tl-wrap{border:1px solid var(--srk-border);border-radius:var(--srk-radius);background:var(--srk-card);padding:10px 12px 8px;margin:12px 0}",
    ".srk-tl{display:flex;align-items:flex-end;gap:3px;height:44px}",
    ".srk-tl-cell{flex:1 1 0;min-width:4px;max-width:26px;border:0;padding:0;border-radius:3px 3px 1px 1px;cursor:pointer;opacity:.85}",
    ".srk-tl-cell:hover,.srk-tl-cell:focus-visible{opacity:1;outline:2px solid var(--srk-accent);outline-offset:1px}",
    ".srk-tl-legend{display:flex;flex-wrap:wrap;gap:4px 12px;margin-top:8px;font-size:12px;color:var(--srk-muted)}",
    ".srk-tl-legend span{display:inline-flex;align-items:center;gap:5px;cursor:help}",
    ".srk-list{display:flex;flex-direction:column;gap:8px}",
    ".srk-scan{border:1px solid var(--srk-border);border-radius:var(--srk-radius);background:var(--srk-card);overflow:hidden}",
    ".srk-flash{box-shadow:0 0 0 2px var(--srk-accent)}",
    ".srk-row{display:flex;gap:12px;align-items:center;width:100%;padding:10px 12px;background:none;border:0;color:inherit;",
    "font:inherit;text-align:left;cursor:pointer}.srk-row:hover{background:var(--srk-soft)}",
    ".srk-row:focus-visible{outline:2px solid var(--srk-accent);outline-offset:-2px}",
    ".srk-risk{flex:none;width:46px;height:46px;border-radius:50%;display:grid;place-items:center;font-weight:700;",
    "font-size:15px;font-variant-numeric:tabular-nums;border:3px solid var(--srk-muted)}",
    ".srk-main{flex:1;min-width:0}.srk-tool{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
    ".srk-meta{color:var(--srk-muted);font-size:12px;display:flex;flex-wrap:wrap;gap:4px 10px}",
    ".srk-action{flex:none;font-size:12px;font-weight:600;padding:3px 10px;border-radius:999px;background:var(--srk-soft)}",
    ".srk-caret{flex:none;color:var(--srk-muted);transition:transform .15s}.srk-open .srk-caret{transform:rotate(90deg)}",
    ".srk-detail{border-top:1px solid var(--srk-border);padding:14px 14px 16px}",
    ".srk-meter{position:relative;height:14px;border-radius:7px;overflow:hidden;display:flex;margin:6px 0 4px;cursor:help}",
    ".srk-zone{height:100%;opacity:.85}.srk-marker{position:absolute;top:-3px;bottom:-3px;width:5px;border-radius:2px;",
    "background:currentColor;box-shadow:0 0 0 2px var(--srk-card)}",
    ".srk-scale{display:flex;justify-content:space-between;color:var(--srk-muted);font-size:11px;font-variant-numeric:tabular-nums}",
    ".srk-formula{margin:12px 0;padding:8px 12px;border-radius:8px;background:var(--srk-soft);font-size:13px}",
    ".srk-formula code{font-weight:600;font-size:13px}",
    ".srk-tiers{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:10px;align-items:start}",
    ".srk-tier{border:1px solid var(--srk-border);border-radius:var(--srk-radius);padding:10px 12px;background:var(--srk-card)}",
    ".srk-tier-top{display:flex;align-items:baseline;justify-content:space-between;gap:8px}",
    ".srk-tier-name{font-weight:700}.srk-tier-score{font-size:22px;font-weight:700;font-variant-numeric:tabular-nums;cursor:help}",
    ".srk-help{color:var(--srk-muted);font-size:12px;margin:2px 0 6px}",
    ".srk-top{font-size:12px;margin-top:8px;color:var(--srk-muted)}",
    ".srk-signals{margin-top:8px}",
    ".srk-signals>summary{cursor:pointer;font-size:12px;color:var(--srk-accent);list-style:none;user-select:none}",
    ".srk-signals>summary::-webkit-details-marker{display:none}",
    ".srk-signals>summary::before{content:'▸ ';}.srk-signals[open]>summary::before{content:'▾ ';}",
    ".srk-track{height:8px;border-radius:4px;background:var(--srk-soft);overflow:hidden}",
    ".srk-fill{height:100%;border-radius:4px}",
    ".srk-leaves{margin-top:8px;display:flex;flex-direction:column;gap:8px}",
    ".srk-leaf-top{display:flex;justify-content:space-between;gap:8px;font-size:13px}",
    ".srk-leaf-val{font-variant-numeric:tabular-nums;font-weight:600}",
    ".srk-na .srk-leaf-val{font-weight:400;color:var(--srk-muted);font-style:italic}",
    ".srk-na .srk-track{background:repeating-linear-gradient(45deg,var(--srk-soft) 0 4px,transparent 4px 8px)}",
    ".srk-group{border-left:3px solid var(--srk-border);padding-left:8px;display:flex;flex-direction:column;gap:8px}",
    ".srk-group-title{font-size:12px;color:var(--srk-muted)}",
    ".srk-reasons{display:flex;flex-direction:column;gap:3px;margin-top:4px}",
    ".srk-reason{font-size:12px;padding:3px 8px;border-radius:6px;background:var(--srk-soft)}",
    ".srk-reason code{font-size:11px;color:var(--srk-muted);margin-right:6px}",
    ".srk-kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;font-size:13px}",
    ".srk-kv dt{color:var(--srk-muted)}.srk-kv dd{margin:0;overflow-wrap:anywhere}",
    ".srk-pre{color:inherit;white-space:pre-wrap;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--srk-soft);",
    "border-radius:8px;padding:8px 10px;margin:6px 0 10px}",
    // How-to sections.
    ".srk-howto{border:1px solid var(--srk-border);border-radius:var(--srk-radius);background:var(--srk-card);margin:8px 0;padding:0 12px}",
    ".srk-howto>summary{cursor:pointer;padding:10px 0;list-style:none;display:flex;gap:10px;align-items:baseline}",
    ".srk-howto>summary::-webkit-details-marker{display:none}",
    ".srk-howto>summary::before{content:'▸';color:var(--srk-muted)}.srk-howto[open]>summary::before{content:'▾'}",
    ".srk-howto-title{font-weight:600}.srk-howto-state{color:var(--srk-muted);font-size:12px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
    ".srk-howto-body{padding:0 0 12px;font-size:13px}.srk-howto-body p{margin:6px 0}",
    ".srk-cmds{display:flex;flex-direction:column;gap:6px;margin:8px 0}",
    ".srk-cmd{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:2px 8px;align-items:center}",
    ".srk-cmd code{display:block;font-size:12px;padding:5px 8px;border-radius:6px;background:var(--srk-soft);overflow-x:auto;white-space:pre}",
    ".srk-cmd-note{grid-column:1/-1;color:var(--srk-muted);font-size:12px}",
    ".srk-note{color:var(--srk-muted);font-size:12px;margin-top:20px}",
    // Search.
    ".srk-search{display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;border:1px solid var(--srk-border);border-radius:var(--srk-radius);background:var(--srk-card);padding:10px 12px;margin:0 0 10px}",
    ".srk-field{display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--srk-muted)}",
    ".srk-field input,.srk-field select{font:inherit;font-size:13px;color:inherit;background:var(--srk-soft);border:1px solid var(--srk-border);border-radius:6px;padding:4px 8px;min-width:0}",
    ".srk-field input[type=number]{width:80px}.srk-field input[type=text]{width:160px}",
    ".srk-btn-primary{border-color:var(--srk-accent);color:var(--srk-accent);font-weight:600}",
    ".srk-status{color:var(--srk-muted);font-size:12px;margin:0 0 8px}.srk-status b{color:inherit}",
    ".srk-warn{color:var(--srk-mid)}",
    ".srk-pager{display:flex;gap:8px;justify-content:center;margin:12px 0}",
    ".srk-empty{color:var(--srk-muted);padding:24px;text-align:center;border:1px dashed var(--srk-border);border-radius:var(--srk-radius)}",
    "@media (max-width:560px){.srk-caret{display:none}.srk-row{gap:10px}.srk-action{font-size:11px;padding:2px 8px;max-width:40%;white-space:normal;text-align:center}}",
  ].join("\n");

  function el(tag, attrs, kids) {
    var node = document.createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k) || attrs[k] == null) continue;
        if (k === "class") node.className = attrs[k];
        else if (k === "text") node.textContent = String(attrs[k]);
        else if (k === "style") node.setAttribute("style", attrs[k]);
        else if (k.slice(0, 2) === "on") node.addEventListener(k.slice(2), attrs[k]);
        else node.setAttribute(k, String(attrs[k]));
      }
    }
    (kids || []).forEach(function (kid) {
      if (kid == null || kid === false) return;
      node.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
    });
    return node;
  }

  /** The Sentrook mark as inline SVG. Decorative: the heading next to it says the name. */
  function mark() {
    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "srk-mark");
    svg.setAttribute("viewBox", "0 0 512 512");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    var path = document.createElementNS(ns, "path");
    path.setAttribute("fill", "currentColor");
    path.setAttribute("d", MARK_PATH);
    svg.appendChild(path);
    return svg;
  }

  /** A label with a hover hint, marked so it reads as one. */
  function hinted(tag, text, hint, cls) {
    return el(tag, { class: "srk-hint" + (cls ? " " + cls : ""), title: hint, text: text });
  }

  function ensureStyle(doc) {
    if (doc.getElementById("srk-style")) return;
    var s = doc.createElement("style");
    s.id = "srk-style";
    s.textContent = CSS;
    (doc.head || doc.documentElement).appendChild(s);
  }

  function pct(v) {
    return v == null ? null : Math.round(v * 100);
  }

  /** Colour for a 0-100 risk against the plugin's review and block lines. */
  function riskColour(risk, lines) {
    if (risk == null) return "var(--srk-muted)";
    if (risk >= lines.block_at) return "var(--srk-high)";
    if (risk >= lines.review_at) return "var(--srk-mid)";
    return "var(--srk-low)";
  }

  /** Colour for a 0-1 score; `worse` says whether high or low values are the bad end. */
  function scoreColour(v, worse) {
    if (v == null) return "var(--srk-muted)";
    var bad = worse === "low" ? 1 - v : v;
    if (bad >= 0.6) return "var(--srk-high)";
    if (bad >= 0.3) return "var(--srk-mid)";
    return "var(--srk-low)";
  }

  function bucketColour(bucket) {
    return {
      blocked: "var(--srk-high)",
      review: "var(--srk-mid)",
      observed: "var(--srk-accent)",
      allowed: "var(--srk-low)",
      scan_error: "var(--srk-muted)",
    }[bucket] || "var(--srk-muted)";
  }

  function when(ts) {
    if (!ts) return "unknown time";
    var d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
  }

  /** "in 23 h" / "in 4 min" for a time ahead of now. */
  function until(ts) {
    var ms = new Date(ts).getTime() - Date.now();
    if (!isFinite(ms)) return "";
    if (ms <= 0) return "now";
    var min = Math.round(ms / 60000);
    return min < 60 ? "in " + Math.max(min, 1) + " min" : "in " + Math.round(min / 60) + " h";
  }

  function fill(text, entities) {
    if (!text) return text;
    return text.replace(/\{(E\d+)\}/g, function (m, id) {
      for (var i = 0; i < entities.length; i++) if (entities[i].id === id) return entities[i].display;
      return m;
    });
  }

  /** The plugin's command for `verb` on this host (`/sentrook-grant` or `/sentrook grant`). */
  function cmdOf(model) {
    var prefix = (model.commands && model.commands.prefix) || "/sentrook-";
    return function (verb) {
      return prefix + verb;
    };
  }

  /** A copyable command line with an optional note under it. */
  function command(text, note) {
    var code = el("code", { text: text });
    var btn = el("button", {
      class: "srk-btn",
      type: "button",
      title: "Copy this command",
      text: "Copy",
      onclick: function () {
        try {
          navigator.clipboard.writeText(text).then(
            function () {
              btn.textContent = "Copied";
            },
            function () {
              btn.textContent = "Select and copy";
            },
          );
        } catch (e) {
          btn.textContent = "Select and copy";
        }
      },
    });
    return el("div", { class: "srk-cmd" }, [code, btn, note ? el("div", { class: "srk-cmd-note", text: note }) : null]);
  }

  function bar(v, colour) {
    return el("div", { class: "srk-track" }, [
      el("div", { class: "srk-fill", style: "width:" + (v == null ? 0 : Math.max(2, pct(v))) + "%;background:" + colour }),
    ]);
  }

  function reasonList(reasons, entities) {
    if (!reasons.length) return null;
    return el(
      "div",
      { class: "srk-reasons" },
      reasons.map(function (r) {
        return el("div", { class: "srk-reason", title: HINTS.reason }, [el("code", { text: r.code }), fill(r.text, entities) || ""]);
      }),
    );
  }

  function leafRow(tier, leaf, reasons, entities) {
    var info = LEAF_INFO[leaf.name] || [leaf.name.replace(/_/g, " "), "A signal this page does not describe yet."];
    var colour = scoreColour(leaf.value, TIER_INFO[tier] ? TIER_INFO[tier].worse : "high");
    var mine = reasons.filter(function (r) {
      return r.signal === tier + "." + leaf.name;
    });
    return el("div", { class: "srk-leaf" + (leaf.value == null ? " srk-na" : "") }, [
      el("div", { class: "srk-leaf-top" }, [
        hinted("span", info[0], info[1]),
        el("span", { class: "srk-leaf-val", title: leaf.value == null ? HINTS.na : info[1], text: leaf.value == null ? "not assessed" : String(pct(leaf.value)) }),
      ]),
      bar(leaf.value, colour),
      reasonList(mine, entities),
    ]);
  }

  /** The signals that most drive a tier, for the collapsed card: the worst two that were assessed. */
  function topSignals(tier, info) {
    var scored = tier.leaves.filter(function (l) {
      return l.value != null;
    });
    scored.sort(function (a, b) {
      return info.worse === "low" ? a.value - b.value : b.value - a.value;
    });
    return scored.slice(0, 2).map(function (l) {
      return (LEAF_INFO[l.name] || [l.name])[0] + " " + pct(l.value);
    });
  }

  function tierCard(tier, scan, open) {
    var info = TIER_INFO[tier.name] || { label: tier.name, help: "", combine: "", worse: "high" };
    var plain = tier.leaves.filter(function (l) {
      return TAINT.indexOf(l.name) < 0 || tier.name !== "suspicion";
    });
    var taint = tier.name === "suspicion"
      ? tier.leaves.filter(function (l) {
          return TAINT.indexOf(l.name) >= 0;
        })
      : [];
    var rows = plain.map(function (l) {
      return leafRow(tier.name, l, scan.reasons, scan.entities);
    });
    if (taint.length) {
      rows.push(
        el("div", { class: "srk-group" }, [
          hinted("div", "Untrusted content: untrusted origin × the larger of exposure and session exposure", "These three combine into one signal: content the agent read only counts when it also shaped the call.", "srk-group-title"),
        ].concat(
          taint.map(function (l) {
            return leafRow(tier.name, l, scan.reasons, scan.entities);
          }),
        )),
      );
    }
    var colour = scoreColour(tier.score, info.worse);
    var assessed = tier.leaves.filter(function (l) {
      return l.value != null;
    }).length;
    var top = topSignals(tier, info);
    var signals = el("details", { class: "srk-signals" }, [
      el("summary", { title: HINTS.signals, text: tier.leaves.length + " signals (" + assessed + " assessed)" }),
      el("div", { class: "srk-help", style: "margin-top:6px", text: info.combine }),
      el("div", { class: "srk-leaves" }, rows),
    ]);
    if (open.has(scan.id + ":" + tier.name)) signals.setAttribute("open", "");
    signals.addEventListener("toggle", function () {
      if (signals.open) open.add(scan.id + ":" + tier.name);
      else open.delete(scan.id + ":" + tier.name);
    });
    return el("div", { class: "srk-tier" }, [
      el("div", { class: "srk-tier-top" }, [
        hinted("span", info.label, info.help, "srk-tier-name"),
        el("span", {
          class: "srk-tier-score",
          title: info.label + " " + (tier.score == null ? "not assessed" : pct(tier.score) + " of 100") + ". " + info.combine,
          style: "color:" + colour,
          text: tier.score == null ? "–" : String(pct(tier.score)),
        }),
      ]),
      el("div", { class: "srk-help", text: info.help }),
      bar(tier.score, colour),
      top.length ? el("div", { class: "srk-top", text: (info.worse === "low" ? "Lowest: " : "Highest: ") + top.join(", ") }) : null,
      signals,
    ]);
  }

  function meter(scan, lines) {
    var risk = scan.risk;
    var r = Math.min(Math.max(lines.review_at, 0), 100);
    var b = Math.min(Math.max(lines.block_at, r), 100);
    return el("div", null, [
      el("div", { class: "srk-meter", role: "img", title: HINTS.meter, "aria-label": "Risk " + (risk == null ? "unknown" : Math.round(risk)) + " of 100" }, [
        el("div", { class: "srk-zone", style: "width:" + r + "%;background:var(--srk-low)" }),
        el("div", { class: "srk-zone", style: "width:" + (b - r) + "%;background:var(--srk-mid)" }),
        el("div", { class: "srk-zone", style: "width:" + (100 - b) + "%;background:var(--srk-high)" }),
        risk == null ? null : el("div", { class: "srk-marker", style: "left:calc(" + Math.min(Math.max(risk, 0), 100) + "% - 2px)" }),
      ]),
      el("div", { class: "srk-scale" }, [
        el("span", { text: "0" }),
        hinted("span", "review at " + lines.review_at + " · block at " + lines.block_at, "The plugin's review and block lines (its reviewAt and blockAt settings)."),
        el("span", { text: "100" }),
      ]),
    ]);
  }

  function chip(colour, text, hint) {
    return el("span", { class: "srk-chip", title: hint }, [colour ? el("span", { class: "srk-dot", style: "background:" + colour }) : null, text]);
  }

  function chips(scan) {
    var out = [];
    scan.floors.forEach(function (f) {
      out.push(chip("var(--srk-high)", "Floor: " + (f.floor || "?") + (f.min_risk == null ? "" : " ≥ " + pct(f.min_risk)), HINTS.floor));
    });
    scan.relief.forEach(function (f) {
      out.push(chip("var(--srk-low)", "Relief: " + (f.effect || "?") + (f.grant_ref ? " (grant " + f.grant_ref + ")" : ""), HINTS.relief));
    });
    if (scan.enforced) out.push(chip(null, "Scanner requires: " + scan.enforced, HINTS.enforced));
    if (scan.ceiling) out.push(chip(null, "At most: " + scan.ceiling, HINTS.ceiling));
    scan.flags.forEach(function (f) {
      var h = FLAG_HINTS[f] || [f.replace(/_/g, " "), "A mark the plugin put on this scan."];
      out.push(chip(null, h[0], h[1]));
    });
    return out.length ? el("div", { class: "srk-bar-row" }, out) : null;
  }

  function detail(scan, model, open, opts) {
    opts = opts || {};
    var cmd = cmdOf(model);
    var kids = [];
    if (scan.failure != null) {
      kids.push(el("p", { text: "The scan failed (" + scan.failure + "), so there are no scores. The plugin applied its scan-error setting." }));
    } else {
      kids.push(el("div", { class: "srk-tier-top" }, [
        hinted("span", "Risk", HINTS.risk, "srk-tier-name"),
        el("span", { class: "srk-tier-score", title: HINTS.risk, style: "color:" + riskColour(scan.risk, model.lines), text: scan.risk == null ? "–" : String(Math.round(scan.risk)) }),
      ]));
      kids.push(meter(scan, model.lines));
      kids.push(chips(scan));
      kids.push(el("div", { class: "srk-formula", title: HINTS.formula }, [
        el("code", { text: "risk = consequence × max(suspicion, uncertainty)" }),
        el("div", { class: "srk-help", style: "margin:4px 0 0", text: "Uncertainty grows as confidence falls. Floors can raise the result; relief from grants can lower a signal. Open a score's signals to see what drove it." }),
      ]));
      kids.push(el("div", { class: "srk-tiers" }, scan.tiers.map(function (t) {
        return tierCard(t, scan, open);
      })));
      var known = {};
      scan.tiers.forEach(function (t) {
        t.leaves.forEach(function (l) {
          known[t.name + "." + l.name] = true;
        });
      });
      var other = scan.reasons.filter(function (r) {
        return !r.signal || !known[r.signal];
      });
      if (other.length) {
        kids.push(el("h2", null, [hinted("span", "Other reasons", HINTS.other)]));
        kids.push(reasonList(other, scan.entities));
      }
    }
    var facts = [
      ["Scan id", scan.id, HINTS.id],
      ["Time", when(scan.ts), HINTS.time],
      ["Session", scan.session || "–", HINTS.session],
      ["Step", scan.step == null ? "–" : String(scan.step), HINTS.step],
      ["Mode", scan.mode || "–", HINTS.mode],
      ["Action", scan.action, HINTS.action],
      ["Review", scan.review, HINTS.review],
    ];
    scan.entities.forEach(function (e) {
      facts.push([e.id + (e.kind ? " (" + e.kind + ")" : ""), e.display, HINTS.entity]);
    });
    kids.push(el("h2", { text: "Details" }));
    kids.push(el("dl", { class: "srk-kv" }, facts.reduce(function (acc, f) {
      acc.push(hinted("dt", f[0], f[2]), el("dd", { text: f[1] }));
      return acc;
    }, [])));
    if (!opts.noCommands && (scan.bucket === "blocked" || scan.bucket === "review" || scan.bucket === "observed")) {
      kids.push(el("div", { class: "srk-cmds" }, [
        command(cmd("why") + " " + scan.id.slice(0, 8), "The same scan as text, with any grant that would allow calls like it next time."),
      ]));
    }
    return el("div", { class: "srk-detail" }, kids);
  }

  function scanCard(scan, model, open) {
    var card = el("div", { class: "srk-scan" + (open.has(scan.id) ? " srk-open" : ""), id: "srk-scan-" + scan.id });
    var body = null;
    var colour = riskColour(scan.risk, model.lines);
    var bucket = BUCKETS[scan.bucket] || ["", ""];
    var row = el("button", { class: "srk-row", type: "button", "aria-expanded": open.has(scan.id) ? "true" : "false" }, [
      el("span", { class: "srk-risk", style: "border-color:" + colour + ";color:" + colour, title: HINTS.risk, text: scan.risk == null ? "–" : String(Math.round(scan.risk)) }),
      el("span", { class: "srk-main" }, [
        el("div", { class: "srk-tool", text: scan.tool || "unknown tool" }),
        el("div", { class: "srk-meta" }, [
          el("span", { text: when(scan.ts) }),
          scan.session ? el("span", { text: "session " + scan.session }) : null,
          scan.review !== "-" ? el("span", { text: "review: " + scan.review }) : null,
        ]),
      ]),
      el("span", { class: "srk-action", style: "color:" + bucketColour(scan.bucket), title: bucket[1], text: scan.action }),
      el("span", { class: "srk-caret", "aria-hidden": "true", text: "›" }),
    ]);
    function setOpen(want) {
      if (want === open.has(scan.id)) return;
      if (want) {
        open.add(scan.id);
        body = detail(scan, model, open);
        card.appendChild(body);
      } else {
        open.delete(scan.id);
        if (body) card.removeChild(body);
        body = null;
      }
      card.className = "srk-scan" + (want ? " srk-open" : "");
      row.setAttribute("aria-expanded", want ? "true" : "false");
    }
    row.addEventListener("click", function () {
      setOpen(!open.has(scan.id));
    });
    card.appendChild(row);
    if (open.has(scan.id)) {
      body = detail(scan, model, open);
      card.appendChild(body);
    }
    card.srkOpen = setOpen;
    return card;
  }

  function timeline(model, cards) {
    var scans = model.scans.slice().reverse();
    var cells = scans.map(function (s) {
      var h = s.risk == null ? 30 : Math.max(18, Math.min(100, s.risk));
      var bucket = BUCKETS[s.bucket] || ["?", ""];
      return el("button", {
        class: "srk-tl-cell",
        type: "button",
        style: "height:" + h + "%;background:" + bucketColour(s.bucket),
        title: (s.tool || "unknown tool") + " · risk " + (s.risk == null ? "–" : Math.round(s.risk)) + " · " + s.action + "\n" + when(s.ts),
        "aria-label": bucket[0] + ": " + (s.tool || "unknown tool"),
        onclick: function () {
          var card = cards[s.id];
          if (!card) return;
          card.srkOpen(true);
          if (card.scrollIntoView) card.scrollIntoView({ behavior: "smooth", block: "start" });
          card.className += " srk-flash";
          setTimeout(function () {
            card.className = card.className.replace(" srk-flash", "");
          }, 1200);
        },
      });
    });
    var legend = Object.keys(BUCKETS)
      .filter(function (k) {
        return model.totals[k];
      })
      .map(function (k) {
        return el("span", { title: BUCKETS[k][1] }, [el("span", { class: "srk-dot", style: "background:" + bucketColour(k) }), BUCKETS[k][0] + " " + model.totals[k]]);
      });
    return el("div", { class: "srk-tl-wrap" }, [
      el("div", { class: "srk-tl", title: HINTS.timeline, role: "list" }, cells),
      el("div", { class: "srk-tl-legend" }, legend.concat([el("span", { class: "srk-spacer" }), el("span", { title: HINTS.timeline, text: "oldest → newest · click to open" })])),
    ]);
  }

  function pendingPanel(model, open) {
    var p = model.pending || {};
    var cmd = cmdOf(model);
    // Pending items carry their own scans: they are read apart from the page's search.
    var reviews = (p.reviews || []).filter(function (s) {
      return s && typeof s === "object";
    });
    var holds = p.holds || [];
    if (!reviews.length && !holds.length) return null;
    var answer = (model.commands && model.commands.review_answer) || [];
    var items = [];
    reviews.forEach(function (s) {
      var deadline = s.ts ? new Date(new Date(s.ts).getTime() + (p.review_window_s || 300) * 1000).toISOString() : null;
      items.push(el("div", { class: "srk-pending-item" }, [
        el("div", { class: "srk-pending-title", text: "Waiting for your answer: " + (s.tool || "unknown tool") + " · risk " + (s.risk == null ? "–" : Math.round(s.risk)) }),
        el("div", { class: "srk-pending-meta", text: when(s.ts) + (s.session ? " · session " + s.session : "") + (deadline ? " · times out " + until(deadline) + " and is denied" : "") }),
        answer.length ? el("div", { class: "srk-help", text: answer[0] }) : null,
        el("div", { class: "srk-cmds" }, answer.slice(1).map(function (c) {
          return command(c);
        }).concat([command(cmd("why") + " " + s.id.slice(0, 8), "The same breakdown as text.")])),
        el("div", { class: "srk-pending-detail" }, [detail(s, model, open, { noCommands: true })]),
      ]));
    });
    holds.forEach(function (h) {
      items.push(el("div", { class: "srk-pending-item" }, [
        el("div", { class: "srk-pending-title", text: "Held for your approval: " + (h.tool || "unknown tool") }),
        el("div", { class: "srk-pending-meta", text: (h.where || "an unattended run") + " · held " + when(h.held_at) + (h.expires_at ? " · expires " + until(h.expires_at) : "") }),
        el("div", { class: "srk-help", text: h.grant
          ? "Approving sets this grant for 30 days, so the next run is allowed: " + h.grant + ". The held call itself does not run again."
          : "There is no suggested grant: approving records your answer and sets nothing." }),
        el("div", { class: "srk-cmds" }, [
          command(cmd("approve") + " " + h.id, "Approve within 24 hours of the hold."),
          command(cmd("why") + " " + h.id, "The held call's scan and what approving would set."),
        ]),
        el("div", { class: "srk-help", text: "To refuse it, do nothing: the hold expires and the call never runs." }),
        h.scan
          ? el("div", { class: "srk-pending-detail" }, [detail(h.scan, model, open, { noCommands: true })])
          : el("div", { class: "srk-help", text: "Its scan is no longer in the traffic log; " + cmd("why") + " " + h.id + " shows it." }),
      ]));
    });
    if (p.holds_readable === false) items.push(el("div", { class: "srk-help", text: "The holds file could not be read, so held calls may be missing here." }));
    return el("section", { class: "srk-pending-section", "aria-label": "Waiting for you" }, [
      el("h2", { class: "srk-section" }, [
        el("span", { class: "srk-dot", style: "background:var(--srk-mid);width:10px;height:10px" }),
        hinted("span", "Waiting for you", "Approval prompts still open and calls held for your approval. Each shows how to answer it."),
        el("span", { class: "srk-section-count", text: String(reviews.length + holds.length) }),
      ]),
    ].concat(items));
  }

  function howto(title, state, body) {
    return el("details", { class: "srk-howto" }, [
      el("summary", null, [el("span", { class: "srk-howto-title", text: title }), el("span", { class: "srk-howto-state", text: state })]),
      el("div", { class: "srk-howto-body" }, body),
    ]);
  }

  function firstLine(text) {
    return String(text || "").split("\n")[0];
  }

  function grantsSection(model) {
    var cmd = cmdOf(model);
    var state = model.state || {};
    return howto("Grants", firstLine(state.grants), [
      el("p", { text: "A grant tells Sentrook something is normal for you: a host, email domain or channel the agent may send to (destination), files it may read, write or delete (file), or an MCP server or plugin it may use (provider). It lowers the matching signals; it never lowers a floor, and a file grant never covers a call that also sends data off the machine." }),
      el("p", { text: "A grant set in chat covers only that session unless you add --persistent. Cron jobs, subagents and other chats need --persistent. --expires sets an end (m, h or d)." }),
      el("pre", { class: "srk-pre", text: state.grants || "–" }),
      el("div", { class: "srk-cmds" }, [
        command(cmd("grants"), "List the grants in force."),
        command(cmd("grant") + " destination api.example.com --persistent --expires 30d", "Let the agent send to one host, in every session, for 30 days."),
        command(cmd("grant") + " destination *.example.com --persistent", "Your own domain: example.com, its subdomains and @example.com addresses."),
        command(cmd("grant") + " file /home/you/notes/* --allows read,write --persistent", "Let the agent read and write one folder."),
        command(cmd("revoke") + " <id>", "Remove a grant set by command, by the id the grants list shows."),
        command(cmd("why") + " <scan id>", "For a reviewed scan: the grant that would let calls like it through next time."),
      ]),
    ]);
  }

  function snoozeSection(model) {
    var cmd = cmdOf(model);
    var state = model.state || {};
    return howto("Snooze", firstLine(state.snooze), [
      el("p", { text: "A snooze lets review prompts through without asking, for a while, in the chat where you set it (or everywhere with --all). Use it while you do setup work that Sentrook keeps asking about." }),
      el("p", { text: "It never allows a block, a review the scanner enforces, or anything on an unattended run. A block with no clear attack signal asks you instead of stopping." }),
      el("pre", { class: "srk-pre", text: state.snooze || "–" }),
      el("div", { class: "srk-cmds" }, [
        command(cmd("snooze"), "This session, for 1 hour."),
        command(cmd("snooze") + " 30m", "This session, for 30 minutes (1m to 24h)."),
        command(cmd("snooze") + " 2h --all", "Every session, for 2 hours."),
        command(cmd("snooze") + " off", "End the snooze in this session (add --all for every session)."),
        command(cmd("snooze") + " status", "What is snoozed now."),
      ]),
    ]);
  }

  var WINDOWS = [
    ["", "Any time"],
    ["1h", "Last hour", 3600e3],
    ["24h", "Last 24 hours", 86400e3],
    ["7d", "Last 7 days", 7 * 86400e3],
    ["custom", "Between…"],
  ];

  /** `2026-11-19T09:00` in this browser's time zone, for a datetime-local input. */
  function localInput(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    var pad = function (n) {
      return (n < 10 ? "0" : "") + n;
    };
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + "T" + pad(d.getHours()) + ":" + pad(d.getMinutes());
  }

  function fromLocalInput(v) {
    if (!v) return null;
    var d = new Date(v);
    return isNaN(d.getTime()) ? null : d.toISOString();
  }

  function mb(bytes) {
    return bytes < 1048576 ? Math.max(1, Math.round(bytes / 1024)) + " KB" : (bytes / 1048576).toFixed(1) + " MB";
  }

  /** The search box. `go(params)` loads a new page: params are the server's query keys. */
  function searchForm(model, go) {
    var q = model.query || {};
    var field = function (label, hint, input) {
      return el("label", { class: "srk-field", title: hint }, [label, input]);
    };
    var tool = el("input", { type: "text", value: q.tool || "", placeholder: "e.g. terminal", maxlength: "80" });
    var outcome = el("select", null, [["", "Any"]].concat(Object.keys(BUCKETS).map(function (k) {
      return [k, BUCKETS[k][0]];
    })).map(function (o) {
      var opt = el("option", { value: o[0], text: o[1] });
      if ((q.outcome || "") === o[0]) opt.setAttribute("selected", "");
      return opt;
    }));
    var custom = q.from || q.to;
    var when = el("select", null, WINDOWS.map(function (w) {
      var opt = el("option", { value: w[0], text: w[1] });
      if ((custom ? "custom" : "") === w[0]) opt.setAttribute("selected", "");
      return opt;
    }));
    var from = el("input", { type: "datetime-local", value: localInput(q.from) });
    var to = el("input", { type: "datetime-local", value: localInput(q.to) });
    var between = el("span", { style: "display:" + (custom ? "contents" : "none") }, [
      field("From", "Scans at or after this time (your time zone).", from),
      field("To", "Scans at or before this time (your time zone).", to),
    ]);
    when.addEventListener("change", function () {
      between.setAttribute("style", "display:" + (when.value === "custom" ? "contents" : "none"));
    });
    var risk = el("input", { type: "number", min: "0", max: "100", value: q.min_risk == null ? "" : String(q.min_risk), placeholder: "0" });
    var size = el("select", null, [10, 25, 50].map(function (n) {
      var opt = el("option", { value: String(n), text: String(n) });
      if (model.limit === n) opt.setAttribute("selected", "");
      return opt;
    }));
    var params = function () {
      var p = { n: size.value, tool: tool.value.trim(), outcome: outcome.value, risk: risk.value.trim() };
      if (q.session) p.session = q.session;
      var w = WINDOWS.filter(function (x) {
        return x[0] === when.value;
      })[0];
      if (w && w[2]) p.from = new Date(Date.now() - w[2]).toISOString();
      if (when.value === "custom") {
        p.from = fromLocalInput(from.value);
        p.to = fromLocalInput(to.value);
      }
      return p;
    };
    // Not a <form>: OpenClaw's tab frame is sandboxed without allow-forms, so a submit would be blocked.
    // The button and Enter navigate instead.
    var search = function () {
      go(params());
    };
    var form = el("div", { class: "srk-search", role: "search" }, [
      field("Tool", "Tool name contains this text (any case).", tool),
      field("Outcome", "Only scans with this outcome.", outcome),
      field("When", "Only scans in this time window. A window also makes the search faster: the log is read only back to its start.", when),
      between,
      field("Risk at least", "Only scans at or above this risk (0 to 100).", risk),
      field("Per page", "How many scans to show at once.", size),
      el("button", { class: "srk-btn srk-btn-primary", type: "button", text: "Search", onclick: search }),
      el("button", {
        class: "srk-btn",
        type: "button",
        text: "Clear",
        title: "Back to the newest scans, no filters.",
        onclick: function () {
          go({ n: String(model.limit || 10) });
        },
      }),
    ]);
    [tool, risk, from, to].forEach(function (input) {
      input.addEventListener("keydown", function (e) {
        if (e && e.key === "Enter") search();
      });
    });
    return form;
  }

  /** What the page shows and how far the log was read; null for a plain first page with nothing to say. */
  function statusLine(model) {
    var q = model.query || {};
    var pg = model.page || {};
    var filtered = !!(q.tool || q.outcome || q.min_risk != null || q.from || q.to || q.session);
    var parts = [];
    if (model.scans.length) {
      parts.push(el("span", { text: "Showing " + model.scans.length + (filtered ? " matching" : "") + " scan" + (model.scans.length === 1 ? "" : "s") + ", newest first" + (q.before ? ", older than the page before" : "") + ". " }));
    } else if (model.log === "on") {
      parts.push(el("span", { text: filtered || q.before ? "No scans match. " : "" }));
    }
    if (pg.read_bytes) parts.push(el("span", { title: "The traffic log has no index: a search reads it backwards from the newest line.", text: "Read " + mb(pg.read_bytes) + " of the log. " }));
    if (pg.budget_hit) parts.push(el("span", { class: "srk-warn", text: "Stopped after the read limit; narrow the time window to look further back. " }));
    if (pg.cursor_lost) parts.push(el("span", { class: "srk-warn", text: "The scan this page continued from is no longer in the log; start again from the newest. " }));
    if (pg.reached_start && !pg.more && (filtered || q.before)) parts.push(el("span", { text: "That is everything in the log for this search." }));
    var text = parts.filter(function (p) {
      return p.textContent;
    });
    return text.length ? el("p", { class: "srk-status" }, text) : null;
  }

  function pager(model, go) {
    var q = model.query || {};
    var pg = model.page || {};
    var keep = function () {
      var p = { n: String(model.limit || 10) };
      ["tool", "outcome", "session", "from", "to"].forEach(function (k) {
        if (q[k]) p[k] = q[k];
      });
      if (q.min_risk != null) p.risk = String(q.min_risk);
      return p;
    };
    var buttons = [];
    if (q.before) {
      buttons.push(el("button", { class: "srk-btn", type: "button", text: "← Newest", title: "Back to the newest scans for this search.", onclick: function () {
        go(keep());
      } }));
    }
    if (pg.more && pg.next) {
      buttons.push(el("button", { class: "srk-btn srk-btn-primary", type: "button", text: "Older →", title: "The next " + (model.limit || 10) + " older scans for this search.", onclick: function () {
        var p = keep();
        p.before = pg.next;
        go(p);
      } }));
    }
    return buttons.length ? el("div", { class: "srk-pager" }, buttons) : null;
  }

  /** Drops empty values: the query string the page sends. */
  function queryString(params) {
    var out = [];
    for (var k in params) {
      if (Object.prototype.hasOwnProperty.call(params, k) && params[k] != null && params[k] !== "") {
        out.push(encodeURIComponent(k) + "=" + encodeURIComponent(params[k]));
      }
    }
    return out.join("&");
  }

  function render(root, model, opts) {
    ensureStyle(root.ownerDocument || document);
    opts = opts || {};
    model = model || {};
    model.scans = model.scans || [];
    model.totals = model.totals || {};
    model.lines = model.lines || { review_at: 45, block_at: 80 };
    var go = opts.navigate || function () {};
    var open = opts.open || new Set();
    // The newest scan opens on first draw; later draws keep what the viewer opened or closed.
    if (opts.openFirst !== false && !open.size && model.scans.length) open.add(model.scans[0].id);
    while (root.firstChild) root.removeChild(root.firstChild);
    root.className = "srk" + (opts.standalone ? " srk-standalone" : "");
    var cmd = cmdOf(model);
    root.appendChild(el("div", { class: "srk-head" }, [
      mark(),
      el("h1", { text: "Sentrook" }),
      el("span", { class: "srk-sub", text: "read-only · mode: " + (model.mode || "?") }),
    ]));
    var pending = pendingPanel(model, open);
    if (pending) root.appendChild(pending);
    root.appendChild(el("h2", { class: "srk-section" }, [
      hinted("span", "History", "Scans from the traffic log, newest first. Search by tool, outcome, time or risk; page back with Older."),
      model.scans.length ? el("span", { class: "srk-section-count", text: String(model.scans.length) }) : null,
    ]));
    if (model.log !== "on") {
      root.appendChild(el("div", { class: "srk-empty", text: "The traffic log is off, so there is no scan history." }));
    } else {
      root.appendChild(searchForm(model, go));
      var status = statusLine(model);
      if (status) root.appendChild(status);
      if (!model.scans.length) {
        var q = model.query || {};
        var any = q.tool || q.outcome || q.min_risk != null || q.from || q.to || q.session || q.before;
        root.appendChild(el("div", { class: "srk-empty", text: any ? "No scans match this search." : "No scans in the traffic log yet." }));
      } else {
        var cards = {};
        var list = el("div", { class: "srk-list" }, model.scans.map(function (s) {
          var card = scanCard(s, model, open);
          cards[s.id] = card;
          return card;
        }));
        root.appendChild(timeline(model, cards));
        root.appendChild(list);
      }
      var more = pager(model, go);
      if (more) root.appendChild(more);
    }
    root.appendChild(el("h2", { text: "Change what Sentrook allows" }));
    root.appendChild(grantsSection(model));
    root.appendChild(snoozeSection(model));
    root.appendChild(el("p", {
      class: "srk-note",
      text: "This page only reads. Run the commands above in a direct chat with the agent; " + cmd("history") + " and " + cmd("why") + " show the same scans as text.",
    }));
  }

  function renderError(root, message) {
    ensureStyle(root.ownerDocument || document);
    while (root.firstChild) root.removeChild(root.firstChild);
    root.className = "srk";
    root.appendChild(el("div", { class: "srk-empty", text: message }));
  }

  var SDK = typeof window !== "undefined" ? window.__HERMES_PLUGIN_SDK__ : undefined;
  var HOST = typeof window !== "undefined" ? window.__HERMES_PLUGINS__ : undefined;

  if (SDK && HOST && typeof HOST.register === "function") {
    // Hermes dashboard tab: fetch the model from the plugin's own API through the SDK (it adds the session token).
    var React = SDK.React;
    var SentrookPage = function () {
      var ref = React.useRef(null);
      var openRef = React.useRef(new Set());
      var drawnRef = React.useRef(false);
      var queryState = React.useState("n=10");
      var query = queryState[0];
      var setQuery = queryState[1];
      React.useEffect(function () {
        var alive = true;
        SDK.fetchJSON("/api/plugins/sentrook/model?" + query)
          .then(function (model) {
            if (!alive || !ref.current) return;
            render(ref.current, model, {
              navigate: function (params) {
                setQuery(queryString(params));
              },
              open: openRef.current,
              openFirst: !drawnRef.current,
            });
            drawnRef.current = true;
          })
          .catch(function () {
            if (alive && ref.current) renderError(ref.current, "The Sentrook dashboard could not load its data. Check that the plugin is enabled.");
          });
        return function () {
          alive = false;
        };
      }, [query]);
      return React.createElement("div", { ref: ref, className: "srk" });
    };
    HOST.register("sentrook", SentrookPage);
  } else if (typeof document !== "undefined") {
    // OpenClaw Control UI tab: the model is embedded in the page.
    var data = document.getElementById("sentrook-model");
    var root = document.getElementById("sentrook-root");
    if (data && root) {
      // `data-theme="host"`: take colours from the page's own theme variables (the local preview of Hermes).
      var standalone = root.getAttribute("data-theme") !== "host";
      if (standalone) document.documentElement.className = "srk-page";
      try {
        render(root, JSON.parse(data.textContent || "{}"), {
          standalone: standalone,
          navigate: function (params) {
            window.location.search = "?" + queryString(params);
          },
        });
      } catch (e) {
        renderError(root, "The Sentrook dashboard could not draw its data.");
      }
    }
  }
})();
