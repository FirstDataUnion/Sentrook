"""Shared PlanIR scanner fixture paths and loaders."""

from __future__ import annotations

import json
from pathlib import Path

from sentrook.planir import PlanIR

ROOT = Path(__file__).resolve().parents[3]
RULES = ROOT / "rules"
PLAN_FIXTURES = ROOT / "fixtures" / "plans"

# (fixture filename, expected L2 decision) — used by test_scan and sanitize parity tests.
L2_DECISION_FIXTURES: list[tuple[str, str]] = [
    ("safe_read_only.json", "allow"),
    ("web_fetch_exec_block.json", "block"),
    ("pending_exec.json", "review"),
    ("curl_bash_exec.json", "block"),
    ("supply_chain_pip_url_exec.json", "block"),
    ("supply_chain_base64_bash.json", "block"),
    ("supply_chain_pip_benign.json", "review"),
    ("exec_obfuscation_eval_curl.json", "block"),
    ("exec_obfuscation_subshell.json", "block"),
    ("exec_obfuscation_benign.json", "review"),
    ("write_etc.json", "block"),
    ("write_authorized_keys_direct.json", "block"),
    ("ingest_search_memory_benign.json", "review"),
    ("ingest_read_memory_benign.json", "review"),
    ("web_search_write_review.json", "review"),
    ("fetch_docs_config_benign.json", "review"),
    ("fetch_stale_exec_benign.json", "review"),
    ("exec_openclaw_config_get_benign.json", "review"),
    ("exec_wiki_edit_sensitive_review.json", "review"),
]


def load_plan_fixture(name: str) -> PlanIR:
    with (PLAN_FIXTURES / name).open(encoding="utf-8") as handle:
        return PlanIR.model_validate(json.load(handle))
