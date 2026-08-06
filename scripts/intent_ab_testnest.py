#!/usr/bin/env python3
"""A/B: authored vs derived/null/hybrid corpus intents under TestNest ambiguous/L3.

Does not change the live feedback path — only builds temporary corpus dirs and
runs TestNest so we can see whether intent shape moves L3 outcomes.

Arms
----
baseline  — repo corpus as-is
derived   — intent rewritten from steps (proposed community-feedback shape)
ablation  — intent cleared (no ``intent:`` line in embed text)
hybrid    — keep authored examples and append a derived clone of each
            (simulates curated + community-derived coexistence; worst-case 1:1)

Plan fixture intents are left unchanged (closer to production: scan still has
prompt-like intent; only the corpus index side changes).
"""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
CORPUS_SRC = REPO / "corpus"


def derive_intent(example: dict) -> str:
    kind = example.get("intent_kind") or "user"
    steps = example.get("steps") or []
    tools = [str(s.get("tool") or "?") for s in steps]
    traj = "→".join(tools) if tools else "unknown"
    pending = next(
        (s for s in reversed(steps) if s.get("status") == "pending"),
        steps[-1] if steps else None,
    )
    brief = ""
    if isinstance(pending, dict):
        args = pending.get("args") or {}
        for key in ("command", "url", "path", "file_path", "query"):
            if key in args and args[key] is not None:
                brief = str(args[key]).replace("\n", " ").strip()
                break
        if not brief:
            brief = str(pending.get("tool") or "")
    if len(brief) > 80:
        brief = brief[:77] + "..."
    text = f"{kind}: {traj} — {brief}".strip(" —")
    return text[:200]


def rewrite_corpus(src: Path, dest: Path, *, mode: str) -> int:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    count = 0
    for path in sorted(dest.glob("AIRA-*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        examples = doc.get("examples") or []
        for ex in examples:
            if mode == "derived":
                ex["intent"] = derive_intent(ex)
            elif mode == "ablation":
                ex["intent"] = None
            else:
                raise ValueError(mode)
            count += 1
        path.write_text(
            yaml.safe_dump(doc, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
    return count


def build_hybrid_corpus(src: Path, dest: Path) -> tuple[int, int]:
    """Keep authored rows; append a derived-intent clone of each example."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    originals = 0
    clones = 0
    for path in sorted(dest.glob("AIRA-*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        examples = list(doc.get("examples") or [])
        originals += len(examples)
        merged: list[dict] = []
        for ex in examples:
            merged.append(ex)
            clone = copy.deepcopy(ex)
            clone["id"] = f"{ex['id']}-derived"
            clone["intent"] = derive_intent(ex)
            notes = clone.get("notes") or ""
            clone["notes"] = f"{notes} [hybrid-derived-clone]".strip()
            if clone.get("trust") == "verified":
                clone["trust"] = "community"
            merged.append(clone)
            clones += 1
        doc["examples"] = merged
        path.write_text(
            yaml.safe_dump(doc, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
    return originals, clones


def run_testnest(corpus: Path, out_json: Path) -> dict:
    cmd = [
        str(REPO / ".venv" / "bin" / "testnest"),
        "run",
        "--suite",
        "ambiguous",
        "--profile",
        "l3_primary",
        "--corpus",
        str(corpus),
        "--rules",
        str(REPO / "rules"),
        "--format",
        "json",
    ]
    proc = subprocess.run(
        cmd,
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    out_json.write_text(proc.stdout, encoding="utf-8")
    if proc.returncode not in (0, 1):
        # 1 = scenario failures; other codes are runner errors
        sys.stderr.write(proc.stderr or proc.stdout)
        raise SystemExit(f"testnest failed rc={proc.returncode}")
    return json.loads(proc.stdout)


def summarize(report: dict) -> tuple[int, int, dict[str, dict]]:
    results = {r["name"]: r for r in report["results"]}
    failed = sum(1 for r in results.values() if r["outcome"] != "passed")
    return len(results), failed, results


def classify_deltas(
    baseline: dict[str, dict], other: dict[str, dict]
) -> tuple[list[str], list[str], list[str]]:
    lost_allow: list[str] = []
    gained_allow: list[str] = []
    other_chg: list[str] = []
    for name in sorted(baseline):
        a, b = baseline[name], other[name]
        if a["outcome"] == b["outcome"] and a.get("scan_summary") == b.get("scan_summary"):
            continue
        a_sum = a.get("scan_summary") or ""
        b_sum = b.get("scan_summary") or ""
        if "Allowed after L3" in a_sum and "Allowed after L3" not in b_sum:
            lost_allow.append(name)
        elif "Allowed after L3" in b_sum and "Allowed after L3" not in a_sum:
            gained_allow.append(name)
        else:
            other_chg.append(f"{name}: {a['outcome']}/{a_sum} → {b['outcome']}/{b_sum}")
    return lost_allow, gained_allow, other_chg


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path("/tmp/sentrook-intent-ab"),
        help="Where to write corpus copies and JSON reports",
    )
    parser.add_argument(
        "--skip-run",
        action="store_true",
        help="Only rewrite corpus dirs; do not invoke TestNest",
    )
    parser.add_argument(
        "--arms",
        default="baseline,derived,ablation,hybrid",
        help="Comma-separated arms to build/run",
    )
    args = parser.parse_args()
    work: Path = args.work_dir
    work.mkdir(parents=True, exist_ok=True)
    wanted = {a.strip() for a in args.arms.split(",") if a.strip()}

    dirs: dict[str, Path] = {}
    if "baseline" in wanted:
        baseline_dir = work / "corpus-baseline"
        if baseline_dir.exists():
            shutil.rmtree(baseline_dir)
        shutil.copytree(CORPUS_SRC, baseline_dir)
        dirs["baseline"] = baseline_dir
    if "derived" in wanted:
        derived_dir = work / "corpus-derived"
        n = rewrite_corpus(CORPUS_SRC, derived_dir, mode="derived")
        print(f"derived: rewrote {n} intents → {derived_dir}")
        dirs["derived"] = derived_dir
    if "ablation" in wanted:
        ablation_dir = work / "corpus-ablation"
        n = rewrite_corpus(CORPUS_SRC, ablation_dir, mode="ablation")
        print(f"ablation: cleared {n} intents → {ablation_dir}")
        dirs["ablation"] = ablation_dir
    if "hybrid" in wanted:
        hybrid_dir = work / "corpus-hybrid"
        n_orig, n_clone = build_hybrid_corpus(CORPUS_SRC, hybrid_dir)
        print(f"hybrid: {n_orig} authored + {n_clone} derived clones → {hybrid_dir}")
        dirs["hybrid"] = hybrid_dir

    if "derived" in dirs:
        sample = yaml.safe_load((dirs["derived"] / "AIRA-058.yaml").read_text(encoding="utf-8"))
        print("sample derived intents (AIRA-058):")
        for ex in sample["examples"][:3]:
            print(f"  {ex['id']}: {ex['intent']}")

    if args.skip_run:
        return

    reports: dict[str, dict] = {}
    for name, corpus in dirs.items():
        print(f"\n=== testnest ambiguous/l3_primary corpus={name} ===")
        report = run_testnest(corpus, work / f"kz-{name}.json")
        total, failed, by_name = summarize(report)
        reports[name] = by_name
        print(f"{name}: {total - failed}/{total} passed (failed={failed})")

    if "baseline" not in reports:
        return
    base = reports["baseline"]
    for name in dirs:
        if name == "baseline":
            continue
        lost, gained, other = classify_deltas(base, reports[name])
        print(f"\n--- {name} vs baseline ---")
        print(f"changed scenarios: {len(lost) + len(gained) + len(other)}")
        print(f"lost L3 allow: {len(lost)}")
        for item in lost:
            print(f"  - {item}")
        print(f"gained L3 allow: {len(gained)}")
        for item in gained:
            print(f"  - {item}")
        if other:
            print(f"other: {len(other)}")
            for line in other[:20]:
                print(f"  {line}")


if __name__ == "__main__":
    main()
