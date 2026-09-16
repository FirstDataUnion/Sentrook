#!/usr/bin/env python3
"""Generate secret-detection rules for both languages from the vendored gitleaks catalogue.

Sentrook does not maintain its own secret-pattern catalogue. gitleaks already
publishes 200+ MIT-licensed rules with entropy thresholds, is already trusted in
this repo (``.gitleaks.toml``, ``useDefault = true``, run in CI), and — because
Go's RE2 has no lookaround — every one of its regexes falls inside the subset
that both Python ``re`` and JavaScript ``RegExp`` accept. Porting is mechanical.

Inputs   sentrook/sanitize/vendor/gitleaks.toml  (pinned; bump deliberately)
Outputs  sentrook/sanitize/gitleaks_rules.json   (Python-flavoured regexes)
         integrations/openclaw/plugin/gitleaksRules.ts (JS-flavoured, bundled)

Run: make gitleaks-rules
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "sentrook" / "sentrook" / "sanitize" / "vendor" / "gitleaks.toml"
PY_OUT = ROOT / "sentrook" / "sentrook" / "sanitize" / "gitleaks_rules.json"
TS_OUT = ROOT / "integrations" / "openclaw" / "plugin" / "gitleaksRules.ts"

#: Rules excluded from the runtime redactor, with the reason. Not a silent skip:
#: every exclusion is a deliberate, reviewable decision.
EXCLUDED: dict[str, str] = {}

# `generic-api-key` was held back pending a false-positive measurement, since it
# is deliberately broad — `(?i)…(key|secret|token|password)\s*=\s*<value>` at
# entropy 3.5 — and on a marker-bearing path over-redaction is not free:
# identical markers on a repeated blob fabricate the cross-step "same value"
# signal Phase 4 reads as dataflow.
#
# Measured on 553 real commands (the full corpus plus common dev invocations):
# it fired **once, 0.2%**, and that hit was a fixture already containing
# `openai=sk-proj-…` — a true positive. Enabled. Re-measure against
# `eval/traffic/` once the soak has volume, since tool *output* is a different
# population from argv.


#: POSIX character classes: valid in Go's RE2, but Python parses ``[[:alnum:]]``
#: as a *nested set* (matching the literal characters ``[:alnum]``) and JS rejects
#: it outright. A silent semantic divergence in a redactor is the worst kind, so
#: these are translated explicitly and anything unrecognised aborts the build.
_POSIX_CLASSES = {
    "[:alnum:]": "A-Za-z0-9",
    "[:alpha:]": "A-Za-z",
    "[:digit:]": "0-9",
    "[:xdigit:]": "0-9A-Fa-f",
    "[:upper:]": "A-Z",
    "[:lower:]": "a-z",
    "[:space:]": r"\s",
    "[:word:]": r"\w",
    "[:punct:]": r"!-/:-@\[-`{-~",
}


def _expand_posix(regex: str) -> str:
    for posix, expansion in _POSIX_CLASSES.items():
        regex = regex.replace(posix, expansion)
    return regex


#: Inline modifier groups — `(?i:…)`, `(?-i:…)`, `(?s:…)`.
#:
#: Valid in Go's RE2, valid in Python 3.11+, and valid in V8 only from Node 23
#: (they are an ES2025 feature). The plugin ships to whatever Node a host runs,
#: so emitting them verbatim made `new RegExp` throw on Node 22 — and since the
#: catalogue is compiled eagerly with no guard, that took **secret redaction
#: down entirely**, not just one rule. CI caught it only because CI pins Node 22
#: while development ran on 24.
#:
#: Every translation below is a **broadening**: the resulting pattern matches at
#: least what the original did. That direction is deliberate. A detector that
#: over-matches redacts something it need not; one that under-matches leaks a
#: credential. The generator refuses anything it cannot translate this way.
_DOTALL_GROUP = re.compile(r"\(\?s:\.\)")


def _expand_modifier_groups(regex: str, ignorecase: bool) -> tuple[str, bool]:
    """Remove inline modifier groups, broadening rather than narrowing.

    Returns the rewritten source and the (possibly hoisted) ignorecase flag.
    """
    # `(?s:.)` — dotall for a single `.`. Exact: `[\s\S]` is what dotall means.
    out = _DOTALL_GROUP.sub(r"[\\s\\S]", regex)

    # `(?i:…)` — hoist to the whole-pattern flag. Broadens the rest of the
    # pattern to case-insensitive, which for the value halves (hex, base64) is
    # still the same character set in a different case.
    if "(?i:" in out:
        ignorecase = True
        out = out.replace("(?i:", "(?:")

    # `(?-i:…)` — a case-*sensitive* island inside a case-insensitive pattern,
    # which JS cannot express once the `i` flag is set. Dropping it widens the
    # island to case-insensitive. Every occurrence in the catalogue guards a
    # keyword (`ATLASSIAN`, `[Ss]umo`, `[Aa]pi`), never the credential itself,
    # so the value constraint that makes the rule precise is untouched.
    out = out.replace("(?-i:", "(?:")

    return out, ignorecase


def _assert_no_modifier_groups(rid: str, src: str, lang: str) -> bool:
    """D16: fail the build rather than emit something a target cannot compile."""
    leftover = re.search(r"\(\?[-a-zA-Z]+:", src)
    if leftover and not leftover.group(0).startswith("(?:"):
        print(
            f"error: {rid} has an untranslated inline modifier group "
            f"{leftover.group(0)!r} in the {lang} source",
            file=sys.stderr,
        )
        return False
    return True


def to_python(regex: str) -> tuple[str, bool]:
    """Go RE2 source -> (Python source, ignorecase). Mechanical only.

    Python accepts inline modifier groups natively, but they are expanded here
    too: the two languages must stay byte-identical in *behaviour*, and a shared
    parity fixture asserts zero divergence. Keeping the construct on one side
    only would reintroduce exactly the drift D16 exists to prevent.
    """
    ignorecase = "(?i)" in regex
    out = _expand_posix(regex.replace("(?i)", ""))
    out, ignorecase = _expand_modifier_groups(out, ignorecase)
    out = out.replace(r"\z", r"\Z")
    return out, ignorecase


def to_javascript(regex: str) -> tuple[str, bool]:
    """Go RE2 source -> (JS source, ignorecase). Mechanical only."""
    ignorecase = "(?i)" in regex
    out = _expand_posix(regex.replace("(?i)", ""))
    out, ignorecase = _expand_modifier_groups(out, ignorecase)
    out = out.replace(r"\z", "$")
    out = re.sub(r"\(\?P<", "(?<", out)  # Go named groups -> JS named groups
    return out, ignorecase


def main() -> int:
    doc = tomllib.loads(VENDOR.read_text(encoding="utf-8"))
    version = str(doc.get("minVersion") or "unknown")
    rules = [r for r in doc["rules"] if "regex" in r]

    py_rules, ts_rules, skipped = [], [], []
    for rule in rules:
        rid = str(rule["id"])
        if rid in EXCLUDED:
            skipped.append(rid)
            continue
        py_src, py_ci = to_python(rule["regex"])
        js_src, js_ci = to_javascript(rule["regex"])
        if "[:" in py_src or "[:" in js_src:
            print(f"error: {rid} has an untranslated POSIX class: {py_src}", file=sys.stderr)
            return 1
        if not _assert_no_modifier_groups(rid, py_src, "Python"):
            return 1
        if not _assert_no_modifier_groups(rid, js_src, "JavaScript"):
            return 1
        try:
            with warnings.catch_warnings():
                # A FutureWarning here means Python read the pattern differently
                # from Go — treat it as a build failure, never a warning.
                warnings.simplefilter("error")
                re.compile(py_src, re.IGNORECASE if py_ci else 0)
        except (re.error, FutureWarning) as exc:  # pragma: no cover - generator guard
            print(f"error: {rid} does not port cleanly to Python: {exc}", file=sys.stderr)
            return 1
        entropy = rule.get("entropy")
        # The *index of the capture group* holding the credential within a
        # match — an integer like 1, never a credential itself.
        group = rule.get("secretGroup")
        py_rules.append(
            {
                "id": rid,
                "regex": py_src,
                "ignorecase": py_ci,
                "entropy": entropy,
                "secret_group": group,
            }
        )
        ts_rules.append(
            {
                "id": rid,
                "regex": js_src,
                "ignorecase": js_ci,
                "entropy": entropy,
                "secretGroup": group,
            }
        )

    # False positive: this writes detection *patterns*, not credentials. The
    # query follows `secretGroup` (a capture-group index) and rule ids that
    # merely contain "secret"/"key" into these writes. The output is a public
    # catalogue of regexes compiled from a vendored MIT ruleset.
    #
    # The marker below must stay on the line **immediately** above the flagged
    # expression and on one line — `codeql[...]` applies to the next line only,
    # so wrapping the justification into it silently does nothing.
    # codeql[py/clear-text-storage-sensitive-data]
    PY_OUT.write_text(
        json.dumps(
            {
                "_generated": "scripts/generate_gitleaks_rules.py — do not edit by hand",
                "_source": "sentrook/sanitize/vendor/gitleaks.toml (gitleaks, MIT)",
                "gitleaks_min_version": version,
                "excluded": EXCLUDED,
                "rules": py_rules,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    def _ts_entry(rule: dict) -> str:
        entropy = json.dumps(rule["entropy"]) if rule["entropy"] is not None else "null"
        group = json.dumps(rule["secretGroup"]) if rule["secretGroup"] is not None else "null"
        return (
            f"  {{ id: {json.dumps(rule['id'])}, regex: {json.dumps(rule['regex'])}, "
            f"ignorecase: {'true' if rule['ignorecase'] else 'false'}, "
            f"entropy: {entropy}, secretGroup: {group} }}"
        )

    body = ",\n".join(_ts_entry(r) for r in ts_rules)
    # As above — generated detection patterns, not credentials.
    # codeql[py/clear-text-storage-sensitive-data]
    TS_OUT.write_text(
        "// GENERATED by scripts/generate_gitleaks_rules.py — do not edit by hand.\n"
        "// Source: sentrook/sanitize/vendor/gitleaks.toml (gitleaks, MIT licensed).\n"
        "// Regenerate with `make gitleaks-rules`, then run both test suites.\n"
        f"// gitleaks minVersion: {version}\n\n"
        "export type GitleaksRule = {\n"
        "  id: string;\n"
        "  regex: string;\n"
        "  ignorecase: boolean;\n"
        "  entropy: number | null;\n"
        "  secretGroup: number | null;\n"
        "};\n\n"
        "export const GITLEAKS_RULES: GitleaksRule[] = [\n" + body + ",\n];\n",
        encoding="utf-8",
    )

    print(
        f"gitleaks catalogue: {len(rules)} rules, {len(py_rules)} emitted, {len(skipped)} excluded"
    )
    for rid in skipped:
        print(f"  excluded: {rid} — {EXCLUDED[rid]}")
    print(f"  -> {PY_OUT.relative_to(ROOT)}")
    print(f"  -> {TS_OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
