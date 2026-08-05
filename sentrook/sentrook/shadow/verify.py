"""Post-install checks for the Sentrook shadow sidecar and OpenClaw plugin."""

from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class VerifyReport:
    """Structured result from :func:`run_shadow_verify`."""

    sidecar_url: str
    sidecar_ok: bool = False
    sidecar_health: dict[str, Any] | None = None
    plugin_ok: bool | None = None
    plugin_runtime: dict[str, Any] | None = None
    gateway_reachable: bool | None = None
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        if not self.sidecar_ok:
            return False
        if self.plugin_ok is False:
            return False
        if self.gateway_reachable is False:
            return False
        return True


def fetch_sidecar_health_via_compose(
    openclaw_dir: Path,
    *,
    sidecar_service: str = "sentrook-shadow",
    port: int = 9099,
    timeout_sec: float = 15.0,
) -> dict[str, Any]:
    """GET /health from inside the sidecar container (Compose deployments)."""
    script = (
        "import json, urllib.request; "
        f"print(urllib.request.urlopen('http://127.0.0.1:{port}/health', timeout=5).read().decode())"
    )
    cmd = [
        *_docker_compose_base(openclaw_dir),
        "exec",
        "-T",
        sidecar_service,
        "python",
        "-c",
        script,
    ]
    proc = subprocess.run(
        cmd,
        cwd=openclaw_dir,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(detail or f"sidecar health exec failed (exit {proc.returncode})")
    return json.loads(proc.stdout)


def fetch_sidecar_health(url: str, *, timeout_sec: float = 5.0) -> dict[str, Any]:
    """GET ``/health`` from the shadow sidecar base URL."""
    base = url.rstrip("/")
    req = urllib.request.Request(f"{base}/health", method="GET")
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        return json.loads(resp.read().decode("utf-8"))


def verify_sidecar_health(health: dict[str, Any]) -> list[str]:
    """Return human-readable errors for an unhealthy sidecar payload."""
    errors: list[str] = []
    if health.get("status") != "ok":
        errors.append(f"sidecar status is {health.get('status')!r}, expected 'ok'")
    rules_loaded = health.get("rules_loaded")
    if not isinstance(rules_loaded, int) or rules_loaded <= 0:
        errors.append(f"sidecar rules_loaded invalid: {rules_loaded!r}")
    corpus_examples = health.get("corpus_examples")
    if not isinstance(corpus_examples, int) or corpus_examples <= 0:
        errors.append(f"sidecar corpus_examples invalid: {corpus_examples!r}")
    return errors


def _docker_compose_base(openclaw_dir: Path) -> list[str]:
    if _have_docker_compose_plugin():
        return ["docker", "compose"]
    compose = _docker_compose_standalone()
    if compose is None:
        raise FileNotFoundError("docker compose or docker-compose not found")
    return [compose]


def _have_docker_compose_plugin() -> bool:
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def _docker_compose_standalone() -> str | None:
    from shutil import which

    return which("docker-compose")


def gateway_fetch_health(
    openclaw_dir: Path,
    *,
    gateway_service: str,
    sidecar_url: str,
    timeout_sec: float = 10.0,
) -> bool:
    """Check gateway container can reach the sidecar (same Docker network)."""
    script = (
        f"fetch({json.dumps(sidecar_url + '/health')})"
        ".then((r) => r.json())"
        ".then((j) => process.exit(j.status === 'ok' ? 0 : 1))"
        ".catch(() => process.exit(2))"
    )
    cmd = [
        *_docker_compose_base(openclaw_dir),
        "exec",
        "-T",
        gateway_service,
        "node",
        "-e",
        script,
    ]
    proc = subprocess.run(
        cmd,
        cwd=openclaw_dir,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
    )
    return proc.returncode == 0


def inspect_openclaw_plugin_runtime(
    openclaw_dir: Path,
    *,
    gateway_service: str,
    plugin_id: str,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Run ``openclaw plugins inspect --runtime --json`` inside the gateway container."""
    cmd = [
        *_docker_compose_base(openclaw_dir),
        "exec",
        "-T",
        gateway_service,
        "openclaw",
        "plugins",
        "inspect",
        plugin_id,
        "--runtime",
        "--json",
    ]
    proc = subprocess.run(
        cmd,
        cwd=openclaw_dir,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(detail or f"plugins inspect failed (exit {proc.returncode})")
    return json.loads(proc.stdout)


def verify_plugin_runtime(runtime: dict[str, Any], *, plugin_id: str) -> list[str]:
    """Return errors when the plugin is not loaded with shadow hooks."""
    errors: list[str] = []
    status = runtime.get("status")
    if status != "loaded":
        errors.append(f"plugin {plugin_id!r} status is {status!r}, expected 'loaded'")

    hook_count = runtime.get("hookCount")
    if not isinstance(hook_count, int) or hook_count < 1:
        errors.append(f"plugin hookCount invalid: {hook_count!r}")

    typed_hooks = runtime.get("typedHooks") or []
    hook_names = {h.get("name") for h in typed_hooks if isinstance(h, dict)}
    if "before_tool_call" not in hook_names:
        errors.append("before_tool_call hook not registered in typedHooks")
    return errors


def run_shadow_verify(
    *,
    url: str,
    openclaw_dir: Path | None = None,
    gateway_service: str = "openclaw-gateway",
    sidecar_service: str | None = None,
    plugin_id: str = "sentrook-shadow",
    check_plugin: bool = True,
    check_gateway_fetch: bool = True,
    timeout_sec: float = 5.0,
) -> VerifyReport:
    """Run sidecar (+ optional OpenClaw plugin) verification checks."""
    report = VerifyReport(sidecar_url=url.rstrip("/"))

    try:
        if openclaw_dir is not None and sidecar_service:
            health = fetch_sidecar_health_via_compose(
                openclaw_dir,
                sidecar_service=sidecar_service,
                timeout_sec=max(timeout_sec, 15.0),
            )
        else:
            health = fetch_sidecar_health(url, timeout_sec=timeout_sec)
        report.sidecar_health = health
        sidecar_errors = verify_sidecar_health(health)
        report.sidecar_ok = not sidecar_errors
        report.errors.extend(sidecar_errors)
    except (urllib.error.URLError, RuntimeError, json.JSONDecodeError, OSError) as exc:
        report.errors.append(f"sidecar health fetch failed: {exc}")

    if openclaw_dir is None:
        if check_plugin or check_gateway_fetch:
            report.notes.append(
                "skipped OpenClaw checks (pass --openclaw-dir to verify plugin + gateway network)"
            )
        return report

    compose_file = openclaw_dir / "docker-compose.yml"
    if not compose_file.is_file():
        report.errors.append(f"openclaw compose project not found: {compose_file}")
        report.plugin_ok = False
        return report

    if check_gateway_fetch:
        try:
            report.gateway_reachable = gateway_fetch_health(
                openclaw_dir,
                gateway_service=gateway_service,
                sidecar_url=report.sidecar_url,
                timeout_sec=max(timeout_sec, 10.0),
            )
            if not report.gateway_reachable:
                report.errors.append(
                    f"gateway container cannot reach sidecar at {report.sidecar_url}/health"
                )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            report.gateway_reachable = False
            report.errors.append(f"gateway reachability check failed: {exc}")

    if not check_plugin:
        return report

    try:
        runtime = inspect_openclaw_plugin_runtime(
            openclaw_dir,
            gateway_service=gateway_service,
            plugin_id=plugin_id,
        )
        report.plugin_runtime = runtime
        plugin_errors = verify_plugin_runtime(runtime, plugin_id=plugin_id)
        report.plugin_ok = not plugin_errors
        report.errors.extend(plugin_errors)
    except (RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired, OSError) as exc:
        report.plugin_ok = False
        report.errors.append(f"plugin runtime inspect failed: {exc}")

    return report


def format_verify_text(report: VerifyReport) -> str:
    """Operator-readable summary."""
    lines = [
        "=== Sentrook shadow verify ===",
        f"sidecar: {report.sidecar_url}",
    ]
    if report.sidecar_health:
        h = report.sidecar_health
        lines.append(
            f"sidecar health: status={h.get('status')} rules={h.get('rules_loaded')} "
            f"corpus_examples={h.get('corpus_examples')} scanner={h.get('scanner_version')}"
        )
    lines.append(f"sidecar ok: {'yes' if report.sidecar_ok else 'no'}")

    if report.gateway_reachable is not None:
        lines.append(f"gateway → sidecar: {'yes' if report.gateway_reachable else 'no'}")

    if report.plugin_ok is not None:
        hook_count = (report.plugin_runtime or {}).get("hookCount")
        lines.append(f"plugin ok: {'yes' if report.plugin_ok else 'no'} (hookCount={hook_count})")

    for note in report.notes:
        lines.append(f"note: {note}")

    if report.errors:
        lines.append("errors:")
        for err in report.errors:
            lines.append(f"  - {err}")

    lines.append(f"overall: {'PASS' if report.ok else 'FAIL'}")
    return "\n".join(lines)
