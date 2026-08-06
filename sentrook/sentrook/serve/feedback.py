"""Feedback pipeline: sanitize snapshots and submit corpus candidates to Rookery."""

from __future__ import annotations

import json
import re
import urllib.request
from typing import Any, Literal

from pydantic import BaseModel, Field

from sentrook import __version__
from sentrook.corpus.models import CorpusExample, CorpusLabel, CorpusStep
from sentrook.corpus.personal import append_personal_corpus_example
from sentrook.library.rookery_client import rookery_auth_headers
from sentrook.planir import PlanIR, PlanStep
from sentrook.redact import redact_args
from sentrook.sanitize.ingress import maybe_sanitize_planir
from sentrook.sanitize.text import scrub_text
from sentrook.serve.config import FeedbackConfig, ServeConfig

FeedbackResolution = Literal["allow-once", "allow-always", "deny", "timeout", "cancelled"]


class FeedbackRequest(BaseModel):
    """Wire contract for ``POST /feedback`` from the OpenClaw plugin."""

    plan: dict[str, Any]
    resolution: FeedbackResolution
    log: dict[str, Any] | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)


def resolution_to_label(resolution: FeedbackResolution) -> CorpusLabel | None:
    if resolution in ("allow-once", "allow-always"):
        return "benign"
    if resolution == "deny":
        return "attack"
    return None


def _truncate(text: str, limit: int) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def sanitize_text(text: str, *, max_chars: int) -> str:
    return scrub_text(text, max_chars=max_chars, pii=True)


def _ingress_plan(config: ServeConfig, raw: dict[str, Any]) -> PlanIR:
    plan = PlanIR.model_validate(raw)
    cleaned, _ = maybe_sanitize_planir(
        plan,
        enabled=config.server_sanitize_planir,
    )
    return cleaned


def _step_excerpt(step: PlanStep, *, max_chars: int) -> str | None:
    summary = step.result_summary
    if summary is None:
        return None
    commands = summary.extracted.commands if summary.extracted else []
    if commands:
        return sanitize_text(str(commands[0]), max_chars=max_chars)
    if summary.excerpt:
        return sanitize_text(summary.excerpt, max_chars=max_chars)
    return None


def derive_community_intent(
    *,
    intent_kind: str | None,
    steps: list[CorpusStep],
) -> str:
    """Build a short intent from trajectory + pending args (no chat prompt).

    Used for community corpus submissions so Rookery reviewers never see the
    raw agent prompt. Format: ``{kind}: {tool→…} — {brief args}``.
    """
    kind = intent_kind or "user"
    tools = [step.tool for step in steps]
    traj = "→".join(tools) if tools else "unknown"
    pending = next(
        (step for step in reversed(steps) if step.status == "pending"),
        steps[-1] if steps else None,
    )
    brief = ""
    if pending is not None:
        args = pending.args or {}
        for key in ("command", "url", "path", "file_path", "query"):
            if key in args and args[key] is not None:
                brief = str(args[key]).replace("\n", " ").strip()
                break
        if not brief:
            brief = pending.tool
    if len(brief) > 80:
        brief = brief[:77] + "..."
    text = f"{kind}: {traj} — {brief}".strip(" —")
    return text[:200]


def plan_to_corpus_example(
    plan: PlanIR,
    *,
    rule_id: str,
    label: Literal["attack", "benign"],
    example_id: str,
    notes: str | None = None,
    max_excerpt_chars: int = 200,
    derive_intent: bool = False,
) -> CorpusExample:
    steps: list[CorpusStep] = []
    for step in plan.steps:
        steps.append(
            CorpusStep(
                tool=step.tool,
                status=step.status,
                args=redact_args(step.args),
                excerpt=(
                    _step_excerpt(step, max_chars=max_excerpt_chars)
                    if step.status == "executed"
                    else None
                ),
            )
        )
    if derive_intent:
        intent = derive_community_intent(
            intent_kind=plan.intent_kind,
            steps=steps,
        )
    else:
        intent = plan.intent
    return CorpusExample(
        id=example_id,
        label=label,
        trust="community",
        intent=intent,
        intent_kind=plan.intent_kind,
        notes=notes,
        steps=steps,
    )


def pick_rule_id(
    plan: PlanIR | None,
    log: dict[str, Any] | None,
) -> str | None:
    """Pick the winning/causal rule that drove the review/block.

    ``matched_rules`` is unordered for learning purposes: L3 may allow early matches
    while a later rule keeps the review. Prefer the scan's winning/causal rule.
    """
    del plan  # reserved for future snapshot-side hints
    if not log:
        return None

    explicit = log.get("winning_rule_id")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()

    from_summary = _winning_rule_id_from_summary(log.get("summary"))
    if from_summary:
        return from_summary

    matched = _normalize_matched_rules(log.get("matched_rules") or [])
    if not matched:
        return None

    l3_allow = {str(rid) for rid in (log.get("l3_allow_rules") or []) if rid}
    l3_kept = _l3_kept_rule_ids(log)

    if l3_kept:
        kept_set = set(l3_kept)
        kept_matched = [m for m in matched if m["id"] in kept_set]
        if kept_matched:
            return _rank_causal_rule(kept_matched)
        return l3_kept[0]

    actionable = [
        m for m in matched if m.get("action") in ("review", "block") and m["id"] not in l3_allow
    ]
    if actionable:
        return _rank_causal_rule(actionable)

    remaining = [m for m in matched if m["id"] not in l3_allow]
    if remaining:
        return remaining[0]["id"]
    return matched[0]["id"]


def pick_feedback_rule_ids(
    plan: PlanIR | None,
    log: dict[str, Any] | None,
    *,
    resolution: FeedbackResolution,
) -> list[str]:
    """Rules that should receive a corpus example for this resolution.

    - ``deny`` (attack): winning/causal rule only — avoid painting co-firers
      with an operator decision framed by the winner's review copy.
    - ``allow-once`` / ``allow-always`` (fatigue): every post-L3 kept review
      rule, primary first — so co-firing soft rules all learn the benign
      neighbor. Never includes L3-allowed matches.
    """
    primary = pick_rule_id(plan, log)
    if primary is None:
        return []
    if resolution == "deny":
        return [primary]

    kept = _l3_kept_rule_ids(log)
    if not kept:
        return [primary]

    ordered = [primary]
    for rule_id in kept:
        if rule_id not in ordered:
            ordered.append(rule_id)
    return ordered


_SUMMARY_WINNING_RE = re.compile(r"^(?:Review triggered|Blocked) by (?P<rule_id>[A-Za-z0-9_-]+)\b")

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _l3_kept_rule_ids(log: dict[str, Any] | None) -> list[str]:
    if not log:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for rid in log.get("l3_kept_review_rules") or []:
        text = str(rid).strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _winning_rule_id_from_summary(summary: Any) -> str | None:
    if not isinstance(summary, str) or not summary.strip():
        return None
    match = _SUMMARY_WINNING_RE.match(summary.strip())
    if not match:
        return None
    return match.group("rule_id")


def _normalize_matched_rules(raw: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            out.append({"id": item.strip()})
        elif isinstance(item, dict) and item.get("id"):
            out.append(
                {
                    "id": str(item["id"]),
                    "action": item.get("action"),
                    "severity": item.get("severity"),
                    "confidence": item.get("confidence"),
                }
            )
    return out


def _rank_causal_rule(candidates: list[dict[str, Any]]) -> str:
    """Mirror scan aggregate: prefer block, then severity/confidence."""
    blocks = [c for c in candidates if c.get("action") == "block"]
    pool = blocks or [c for c in candidates if c.get("action") == "review"] or candidates

    def key(c: dict[str, Any]) -> tuple:
        try:
            confidence = float(c.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        severity = _SEVERITY_RANK.get(str(c.get("severity") or "medium"), 1)
        return (confidence, severity, c["id"])

    return max(pool, key=key)["id"]


def build_example_id(plan: PlanIR, rule_id: str, label: str) -> str:
    session = (plan.metadata.session_id or "session").replace(":", "-")[:24]
    tool_call = (plan.metadata.tool_call_id or "call").replace(":", "-")[:24]
    return f"fb-{label}-{rule_id.lower()}-{session}-{tool_call}"


def build_submission_body(
    example: CorpusExample,
    *,
    rule_id: str,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": "sentrook.library.submission/v1",
        "kind": "corpus_example",
        "rule_id": rule_id,
        "source": "sentrook_client",
        "example": example.model_dump(mode="json"),
        "provenance": provenance,
    }


def submit_to_rookery(
    url: str,
    body: dict[str, Any],
    *,
    timeout: int = 30,
    api_key: str | None = None,
) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        f"{url.rstrip('/')}/api/v1/submissions",
        data=data,
        headers={
            "Content-Type": "application/json",
            **rookery_auth_headers(api_key),
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def process_feedback(
    config: ServeConfig,
    request: FeedbackRequest,
) -> dict[str, Any]:
    """Sanitize, label, submit, or persist personal corpus from a review."""
    if request.resolution == "allow-always":
        return _process_allow_always(config, request)

    return _submit_feedback(config, request)


def _submit_feedback(
    config: ServeConfig,
    request: FeedbackRequest,
    *,
    example: CorpusExample | None = None,
    rule_id: str | None = None,
    rule_ids: list[str] | None = None,
    plan: PlanIR | None = None,
) -> dict[str, Any]:
    """Submit labelled corpus example(s) to Rookery (shared by allow/deny)."""
    feedback_cfg = config.feedback
    if feedback_cfg.mode == "off":
        return {"status": "skipped", "reason": "feedback disabled"}

    label = resolution_to_label(request.resolution)
    if label is None:
        return {"status": "skipped", "reason": f"resolution {request.resolution} not labelable"}

    if plan is None:
        plan = _ingress_plan(config, request.plan)

    if rule_ids is None:
        if rule_id is not None:
            rule_ids = [rule_id]
        else:
            rule_ids = pick_feedback_rule_ids(
                plan,
                request.log,
                resolution=request.resolution,
            )
    if not rule_ids:
        return {"status": "skipped", "reason": "no matched rule for feedback"}

    primary = rule_ids[0]
    if feedback_cfg.mode != "submit":
        return {
            "status": "skipped",
            "reason": f"unknown feedback mode {feedback_cfg.mode}",
            "rule_id": primary,
            "rule_ids": rule_ids,
            "label": label,
        }

    if not feedback_cfg.rookery_url:
        return {
            "status": "error",
            "reason": "feedback submit enabled but no rookery url",
            "rule_id": primary,
            "rule_ids": rule_ids,
            "label": label,
        }

    notes = (
        "Personal allow-always (live review)"
        if request.resolution == "allow-always"
        else f"Live review feedback ({request.resolution})"
    )
    submissions: list[dict[str, Any]] = []
    for rid in rule_ids:
        if example is not None and rid == primary:
            ex = example
        else:
            ex = plan_to_corpus_example(
                plan,
                rule_id=rid,
                label=label,
                example_id=build_example_id(plan, rid, label),
                notes=notes,
                max_excerpt_chars=feedback_cfg.max_excerpt_chars,
                derive_intent=feedback_cfg.derive_intent,
            )
        provenance = _build_provenance(
            config,
            request,
            plan,
            rid,
            primary_rule_id=primary,
            co_fired_rules=rule_ids,
        )
        body = build_submission_body(ex, rule_id=rid, provenance=provenance)
        try:
            result = submit_to_rookery(
                feedback_cfg.rookery_url,
                body,
                api_key=config.rookery_api_key,
            )
        except Exception as exc:  # noqa: BLE001 — surface as feedback_error
            submissions.append(
                {
                    "status": "feedback_error",
                    "reason": str(exc),
                    "example_id": ex.id,
                    "rule_id": rid,
                    "label": label,
                }
            )
            continue
        submission = result.get("submission", {})
        submissions.append(
            {
                "status": "submitted",
                "example_id": ex.id,
                "rule_id": rid,
                "label": label,
                "submission_id": submission.get("id"),
            }
        )

    return _aggregate_submission_results(
        rule_ids=rule_ids,
        label=label,
        submissions=submissions,
    )


def _aggregate_submission_results(
    *,
    rule_ids: list[str],
    label: CorpusLabel,
    submissions: list[dict[str, Any]],
) -> dict[str, Any]:
    primary = rule_ids[0]
    primary_row = next((s for s in submissions if s.get("rule_id") == primary), None)
    ok = [s for s in submissions if s.get("status") == "submitted"]
    errors = [s for s in submissions if s.get("status") == "feedback_error"]

    if ok and not errors:
        status = "submitted"
    elif ok and errors:
        status = "partial"
    elif errors:
        status = "feedback_error"
    else:
        status = "skipped"

    out: dict[str, Any] = {
        "status": status,
        "rule_id": primary,
        "rule_ids": rule_ids,
        "label": label,
        "submissions": submissions,
    }
    if primary_row:
        out["example_id"] = primary_row.get("example_id")
        if primary_row.get("submission_id") is not None:
            out["submission_id"] = primary_row["submission_id"]
        if primary_row.get("reason"):
            out["reason"] = primary_row["reason"]
    elif submissions:
        out["example_id"] = submissions[0].get("example_id")
        if submissions[0].get("reason"):
            out["reason"] = submissions[0]["reason"]
    if status == "partial":
        out["reason"] = (
            f"{len(ok)}/{len(submissions)} rule submissions succeeded; "
            f"failed={[s.get('rule_id') for s in errors]}"
        )
    elif status == "feedback_error" and errors and "reason" not in out:
        out["reason"] = errors[0].get("reason")
    return out


def _process_allow_always(
    config: ServeConfig,
    request: FeedbackRequest,
) -> dict[str, Any]:
    """Save local personal corpus (if enabled) and also feed Rookery when configured.

    Paths are independent: personal save does not require feedback mode, and
    Rookery submit does not require personal corpus. Hosted scan hosts
    should leave personal corpus disabled; Rookery feedback remains the path.

    Fatigue attribution: personal + community examples go to every post-L3 kept
    review rule (primary first), matching allow-once multi-submit policy.
    """
    plan = _ingress_plan(config, request.plan)
    rule_ids = pick_feedback_rule_ids(
        plan,
        request.log,
        resolution="allow-always",
    )
    if not rule_ids:
        return {"status": "skipped", "reason": "no matched rule for allow-always"}

    primary = rule_ids[0]
    result: dict[str, Any] = {
        "rule_id": primary,
        "rule_ids": rule_ids,
        "label": "benign",
    }

    personal_dir = config.resolved_personal_corpus_dir()
    any_created = False
    personal_paths: list[str] = []
    primary_example_id: str | None = None

    for rid in rule_ids:
        example = plan_to_corpus_example(
            plan,
            rule_id=rid,
            label="benign",
            example_id=build_example_id(plan, rid, "benign"),
            notes="Personal allow-always (live review)",
            max_excerpt_chars=config.feedback.max_excerpt_chars,
            derive_intent=config.feedback.derive_intent,
        )
        if rid == primary:
            primary_example_id = example.id

        if personal_dir is None:
            continue

        saved_id, created = append_personal_corpus_example(
            personal_dir,
            rule_id=rid,
            example=example,
        )
        any_created = any_created or created
        personal_paths.append(str(personal_dir / f"{rid}.yaml"))
        if rid == primary:
            primary_example_id = saved_id

    if personal_dir is not None:
        result["personal_status"] = (
            "personal_corpus_saved" if any_created else "personal_corpus_duplicate"
        )
        result["example_id"] = primary_example_id
        result["path"] = (
            personal_paths[0] if personal_paths else str(personal_dir / f"{primary}.yaml")
        )
        if len(personal_paths) > 1:
            result["paths"] = personal_paths
        result["reload_recommended"] = any_created
    else:
        result["personal_status"] = "personal_corpus_disabled"
        result["example_id"] = primary_example_id

    feedback = _submit_feedback(
        config,
        request,
        rule_ids=rule_ids,
        plan=plan,
    )
    result["feedback_status"] = feedback.get("status")
    result["submissions"] = feedback.get("submissions")
    if feedback.get("submission_id") is not None:
        result["submission_id"] = feedback["submission_id"]
    if feedback.get("reason"):
        result["feedback_reason"] = feedback["reason"]

    # Primary status: prefer a concrete outcome for callers/tests.
    if (
        result["personal_status"].startswith("personal_corpus_")
        and result["personal_status"] != "personal_corpus_disabled"
    ):
        result["status"] = result["personal_status"]
    elif result["feedback_status"] in ("submitted", "partial"):
        result["status"] = result["feedback_status"]
    elif result["feedback_status"] == "feedback_error":
        result["status"] = "feedback_error"
    elif result["feedback_status"] == "error":
        result["status"] = "error"
        result["reason"] = result.get("feedback_reason")
    else:
        result["status"] = "skipped"
        result["reason"] = result.get("feedback_reason") or "nothing to do for allow-always"

    return result


def _build_provenance(
    config: ServeConfig,
    request: FeedbackRequest,
    plan: PlanIR,
    rule_id: str,
    *,
    primary_rule_id: str | None = None,
    co_fired_rules: list[str] | None = None,
) -> dict[str, Any]:
    primary = primary_rule_id or rule_id
    co_fired = list(co_fired_rules or [rule_id])
    attribution = (
        "fatigue_all_kept"
        if request.resolution in ("allow-once", "allow-always") and len(co_fired) > 1
        else "winner_only"
    )
    provenance: dict[str, Any] = {
        "scanner_version": __version__,
        "bundle_version": config.bundle_version,
        "source": "openclaw_review",
        "resolution": request.resolution,
        "session_id": plan.metadata.session_id,
        "run_id": plan.run_id,
        "tool_call_id": plan.metadata.tool_call_id,
        "rule_id": rule_id,
        "primary_rule_id": primary,
        "co_fired_rules": co_fired,
        "attribution": attribution,
        "intent_derived": config.feedback.derive_intent,
        **request.provenance,
    }
    if request.log:
        provenance["scan_log"] = {
            "decision": request.log.get("decision"),
            "summary": request.log.get("summary"),
            "matched_rules": request.log.get("matched_rules"),
            "winning_rule_id": request.log.get("winning_rule_id"),
            "l3_allow_rules": request.log.get("l3_allow_rules"),
            "l3_kept_review_rules": request.log.get("l3_kept_review_rules"),
        }
    return provenance


def feedback_config_summary(cfg: FeedbackConfig) -> dict[str, Any]:
    return {
        "mode": cfg.mode,
        "rookery_url": cfg.rookery_url,
        "max_excerpt_chars": cfg.max_excerpt_chars,
        "derive_intent": cfg.derive_intent,
    }
