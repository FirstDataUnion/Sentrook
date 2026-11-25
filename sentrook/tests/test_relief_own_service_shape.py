"""Only the relief for a key sent to its own service names no grant and takes sensitivity off.

A scan response's `relief_applied` carries a relief's grant, subject and effect, not its reason. The plugins read a
relief that names no grant and whose effect is `sensitivity` or `sensitivity+distrust+untrusted_origin` as the
credential-home relief (`relief.credential_own_service`), and list the call's key names as sent to that host's own
service. This pins that no other relief has that shape: a new grantless relief that takes sensitivity off must give
the plugins another way to tell it apart first.
"""

import ast
from pathlib import Path

import sentrook

PACKAGE = Path(sentrook.__file__).resolve().parent
OWN_SERVICE_EFFECTS = {"sensitivity", "sensitivity+distrust+untrusted_origin"}
OWN_SERVICE = "relief.credential_own_service"


def _relief_calls():
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "Relief"
            ):
                yield path, node


def _literal(node):
    return node.value if isinstance(node, ast.Constant) else ...


def test_reliefs_are_built_only_in_the_relief_module_with_positional_fields():
    calls = list(_relief_calls())
    assert calls
    for path, node in calls:
        assert path.name == "relief.py", path
        assert len(node.args) == 5 and not node.keywords, ast.unparse(node)


def test_a_grantless_relief_that_takes_sensitivity_off_is_the_own_service_relief():
    seen = 0
    for _path, node in _relief_calls():
        grant_ref, _subject, effect, reason, _excluded = node.args
        if _literal(grant_ref) is not None:
            # a grant's relief: its reference is a grant id from the scan's grants, never None
            assert isinstance(grant_ref, ast.Name), ast.unparse(node)
            continue
        # a grantless relief writes its effect and reason out, so its shape can be read here
        effect_text = _literal(effect)
        assert isinstance(effect_text, str), ast.unparse(node)
        reasons = (
            {_literal(reason.body), _literal(reason.orelse)}
            if isinstance(reason, ast.IfExp)
            else {_literal(reason)}
        )
        assert all(isinstance(r, str) for r in reasons), ast.unparse(node)
        if effect_text in OWN_SERVICE_EFFECTS or effect_text.startswith("sensitivity"):
            assert reasons == {OWN_SERVICE}, ast.unparse(node)
            seen += 1
        else:
            assert OWN_SERVICE not in reasons, ast.unparse(node)
    assert seen == 3
