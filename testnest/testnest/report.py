from __future__ import annotations

import json
from pathlib import Path

from testnest.runner import TestNestReport, ScenarioOutcome, ScenarioResult


def format_text_report(report: TestNestReport, *, verbose: bool = False) -> str:
    lines = [
        f"TestNest — profile={report.profile}",
        _format_config_line(report),
        f"  passed={report.passed} failed={report.failed} "
        f"skipped={report.skipped} xfailed={report.xfailed} xpassed={report.xpassed}",
        "",
    ]
    for result in report.results:
        lines.append(_format_result_line(result))
        if verbose or result.outcome in {
            ScenarioOutcome.FAILED,
            ScenarioOutcome.XPASSED,
        }:
            lines.extend(_format_result_detail(result, verbose=verbose))
    lines.append("")
    lines.append("OK" if report.ok else "FAIL")
    return "\n".join(lines)


def write_junit(report: TestNestReport, path: Path) -> None:
    cases = []
    for result in report.results:
        cases.append(_junit_case(result))
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="testnest" tests="{len(report.results)}" '
        f'failures="{report.failed + report.xpassed}" '
        f'skipped="{report.skipped + report.xfailed + sum(1 for r in report.results if r.outcome == ScenarioOutcome.NO_PROFILE)}">\n'
        + "\n".join(cases)
        + "\n</testsuite>\n"
    )
    path.write_text(body, encoding="utf-8")


def _format_config_line(report: TestNestReport) -> str:
    cfg = report.scanner_config or {}
    policy = cfg.get("l3_policy", "off")
    if policy == "off" or not cfg.get("l3"):
        return f"  scanner: l3_policy={policy}"
    l3 = cfg["l3"]
    return (
        f"  scanner: l3_policy={policy} "
        f"model={l3.get('bi_encoder_model')} reranker={l3.get('reranker')} "
        f"allow_margin={l3.get('allow_margin')} "
        f"fail_closed_margin={l3.get('fail_closed_margin')} "
        f"top_k={l3.get('top_k')} corpus={report.corpus_dir}"
    )


def format_json_report(report: TestNestReport) -> str:
    payload = {
        "profile": report.profile,
        "scanner_config": report.scanner_config,
        "corpus_dir": report.corpus_dir,
        "passed": report.passed,
        "failed": report.failed,
        "skipped": report.skipped,
        "xfailed": report.xfailed,
        "xpassed": report.xpassed,
        "ok": report.ok,
        "results": [
            {
                "name": r.scenario.name,
                "tags": r.scenario.tags,
                "profile": r.profile,
                "outcome": r.outcome.value,
                "summary": r.summary,
                "scan_summary": r.scan_summary,
                "failures": [
                    {"field": f.field, "expected": f.expected, "actual": f.actual}
                    for f in r.failures
                ],
            }
            for r in report.results
        ],
    }
    return json.dumps(payload, indent=2)


def _format_result_line(result: ScenarioResult) -> str:
    icon = {
        ScenarioOutcome.PASSED: "✓",
        ScenarioOutcome.FAILED: "✗",
        ScenarioOutcome.SKIPPED: "○",
        ScenarioOutcome.XFAILED: "≈",
        ScenarioOutcome.XPASSED: "!",
        ScenarioOutcome.NO_PROFILE: "·",
    }[result.outcome]
    tag_str = ",".join(result.scenario.tags) if result.scenario.tags else "-"
    return f"  {icon} {result.scenario.name} [{tag_str}] ({result.outcome.value})"


def _format_result_detail(result: ScenarioResult, *, verbose: bool) -> list[str]:
    lines: list[str] = []
    if result.summary:
        lines.append(f"      {result.summary}")
    if result.scan_summary:
        lines.append(f"      scan: {result.scan_summary}")
    for failure in result.failures:
        lines.append(
            f"      {failure.field}: expected {failure.expected}; got {failure.actual}"
        )
    if verbose and result.scenario.description:
        lines.append(f"      desc: {result.scenario.description}")
    return lines


def _junit_case(result: ScenarioResult) -> str:
    name = result.scenario.name
    if result.outcome == ScenarioOutcome.PASSED:
        return f'  <testcase name="{name}" classname="testnest"/>'
    if result.outcome == ScenarioOutcome.SKIPPED:
        reason = result.summary or "skipped"
        return (
            f'  <testcase name="{name}" classname="testnest">'
            f"<skipped message=\"{reason}\"/></testcase>"
        )
    if result.outcome == ScenarioOutcome.XFAILED:
        return (
            f'  <testcase name="{name}" classname="testnest">'
            f"<skipped message=\"xfail\"/></testcase>"
        )
    if result.outcome == ScenarioOutcome.NO_PROFILE:
        return (
            f'  <testcase name="{name}" classname="testnest">'
            f"<skipped message=\"no profile\"/></testcase>"
        )
    msg = result.summary or "; ".join(
        f"{f.field}: {f.actual}" for f in result.failures
    )
    return (
        f'  <testcase name="{name}" classname="testnest">'
        f"<failure message=\"{msg}\"/></testcase>"
    )
