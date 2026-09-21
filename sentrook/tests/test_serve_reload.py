"""`ScanService.reload` must be all-or-nothing.

It used to assign `self.rules` before the corpus load that can raise, so a
bundle whose rules parsed and whose corpus did not left the service running the
**new** rules with the **old** corpus — while the caller saw an exception and
the operator's log said the reload had failed. A rollback bundle removing a
hard review rule applied that removal silently, which is precisely the
fail-open the operator was being told had not happened.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sentrook.serve.config import ServeConfig
from sentrook.serve.service import ScanService

RULE_A = """\
rule: AIRA-900
meta:
  name: keeper
  severity: medium
  action: review
  authority: hard
  description: A hard review the rollback would remove.
condition:
  pending_tool: exec
"""

RULE_B = """\
rule: AIRA-901
meta:
  name: other
  severity: low
  action: review
  authority: soft
  description: A second rule so the set is not a singleton.
condition:
  pending_tool: read
"""

CORPUS = """\
rule_id: AIRA-901
examples:
- id: pos-one
  label: attack
  trust: verified
  label_basis: authored
  intent: read the shadow file
  steps:
  - tool: read
    status: pending
    args:
      path: /etc/shadow
- id: neg-one
  label: benign
  trust: verified
  label_basis: authored
  intent: read my notes
  steps:
  - tool: read
    status: pending
    args:
      path: /tmp/notes.md
"""


@pytest.fixture
def library(tmp_path: Path) -> Path:
    (tmp_path / "rules").mkdir()
    (tmp_path / "corpus").mkdir()
    (tmp_path / "rules" / "AIRA-900.yaml").write_text(RULE_A, encoding="utf-8")
    (tmp_path / "rules" / "AIRA-901.yaml").write_text(RULE_B, encoding="utf-8")
    (tmp_path / "corpus" / "AIRA-901.yaml").write_text(CORPUS, encoding="utf-8")
    return tmp_path


def _service(library: Path) -> ScanService:
    return ScanService(ServeConfig(rules_path=library / "rules", corpus_dir=library / "corpus"))


def test_a_failed_reload_changes_nothing(library: Path) -> None:
    service = _service(library)
    before = ([r.id for r in service.rules], sorted(service.corpus))

    # The shape that bit: rules parse (and drop a hard rule), corpus does not.
    (library / "rules" / "AIRA-900.yaml").unlink()
    (library / "corpus" / "AIRA-901.yaml").write_text("{{{ not yaml", encoding="utf-8")

    with pytest.raises(yaml.YAMLError):
        service.reload()

    assert ([r.id for r in service.rules], sorted(service.corpus)) == before
    assert "AIRA-900" in {r.id for r in service.rules}, (
        "the hard rule was removed by a reload that reported failure"
    )


def test_a_good_reload_still_applies(library: Path) -> None:
    """Without this the test above passes on a `reload` that does nothing."""
    service = _service(library)
    assert "AIRA-900" in {r.id for r in service.rules}

    (library / "rules" / "AIRA-900.yaml").unlink()
    service.reload()

    assert "AIRA-900" not in {r.id for r in service.rules}
    assert "AIRA-901" in {r.id for r in service.rules}
