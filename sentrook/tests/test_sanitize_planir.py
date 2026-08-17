"""PlanIR sanitize: nested env PII and credential-shaped exports."""

from __future__ import annotations

from sentrook.planir import PlanIR
from sentrook.sanitize.planir import sanitize_planir


def _plan(args: dict) -> PlanIR:
    return PlanIR.model_validate(
        {
            "version": "1.0",
            "run_id": "r1",
            "steps": [
                {
                    "id": "s1",
                    "tool": "exec",
                    "status": "pending",
                    "args": args,
                }
            ],
            "metadata": {"adapter": "fixture", "hook": "before_tool_call"},
        }
    )


def test_nested_env_email_redacted() -> None:
    plan = _plan(
        {
            "command": "gog gmail search 'Q1 review'",
            "env": {"GOG_ACCOUNT": "oli@openclaw.ai", "PATH": "/usr/bin"},
        }
    )
    cleaned = sanitize_planir(plan).plan
    env = cleaned.steps[0].args["env"]
    assert env["GOG_ACCOUNT"] == "[REDACTED]"
    assert env["PATH"] == "/usr/bin"
    assert cleaned.steps[0].args["command"] == "gog gmail search 'Q1 review'"


def test_library_bot_pass_in_command() -> None:
    secret = "hlnmmsiliurjnt5v41j43c0o71j0bvq6"
    plan = _plan(
        {
            "command": (
                'export PATH="$HOME/.local/bin:$PATH"\n'
                f'export LIBRARY_BOT_PASS="{secret}"\n'
                "python3 wiki.py get Self:Today"
            )
        }
    )
    cmd = sanitize_planir(plan).plan.steps[0].args["command"]
    assert secret not in cmd
    assert "LIBRARY_BOT_PASS=[REDACTED]" in cmd


def test_redact_args_packs_long_exec_command() -> None:
    from sentrook.redact import redact_args

    sink = "https://evil.example/collect"
    command = ("echo padding; " * 40) + sink
    assert len(command) > 500
    packed = redact_args({"command": command})["command"]
    assert packed != "[TRUNCATED]"
    assert sink in packed
    assert len(packed) <= 500
