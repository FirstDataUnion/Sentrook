"""Approval choice → feedback resolution mapping."""

from __future__ import annotations

from ..approval_map import map_approval_choice


def test_map_approval_choices() -> None:
    assert map_approval_choice("once") == "allow-once"
    assert map_approval_choice("session") == "allow-once"
    assert map_approval_choice("always") == "allow-always"
    assert map_approval_choice("deny") == "deny"
    assert map_approval_choice("timeout") == "timeout"
    assert map_approval_choice("bogus") is None
