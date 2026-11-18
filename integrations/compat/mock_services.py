"""Stand-ins for the identity service, the Sentrook scanner and a model provider, for the host
compatibility checks. Stdlib only: it runs on the host image's own Python.

One server answers all three, on one port:

- identity: OIDC discovery and a client_credentials token endpoint that accepts only the expected
  client id and secret;
- scanner: `/healthz`, and `/scan`, which blocks a pending call that mentions `BLOCKED_FILE` and
  allows every other one;
- model: an OpenAI-compatible `/v1/chat/completions` that asks for two shell calls (the host's shell
  tool, `--tool`: `terminal` on Hermes, `exec` on OpenClaw), one at a time:
  first one that creates `BLOCKED_FILE` (Sentrook should block it), then one that creates
  `ALLOWED_FILE` (Sentrook should allow it), then answers in text. Streaming and non-streaming both
  work.

Every request is appended to the log file as one JSON line (method, path, and the parsed body for
/scan), so the check can see what the plugin sent. Hosts and credentials are synthetic.
"""

from __future__ import annotations

import argparse
import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

BLOCKED_FILE = "/tmp/sentrook-compat-blocked"
ALLOWED_FILE = "/tmp/sentrook-compat-allowed"
#: The model's final answer, which the check looks for in the chat output.
FINAL_ANSWER = "compat turn done"

_log_lock = threading.Lock()


def _jwt(claims: dict[str, Any]) -> str:
    def part(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{part({'alg': 'none', 'typ': 'JWT'})}.{part(claims)}.c2ln"


def scan_response(planir: Any) -> dict[str, Any]:
    """Block the pending call that touches BLOCKED_FILE, allow the rest. Only the pending call is
    judged: the history of a later scan still names the blocked call. Response 2.0, as the plugin
    parses it."""
    pending = planir.get("pending_call") if isinstance(planir, dict) else None
    if BLOCKED_FILE in json.dumps(pending):
        return {
            "response_version": "2.0",
            "status": "ok",
            "risk": 100,
            "enforced": "block",
            "tool_description": {"category": "changes_files", "template": "Writes {E1}"},
            "entities": {"E1": {"kind": "path", "display": BLOCKED_FILE}},
            "reasons": [{"code": "compat.mock_block"}],
        }
    return {"response_version": "2.0", "status": "ok", "risk": 0, "reasons": []}


def model_reply(messages: list[dict[str, Any]], tool: str = "terminal") -> dict[str, Any]:
    """The assistant message for this step: the blocked call, then the allowed call, then text."""
    done = sum(1 for m in messages if m.get("role") == "tool")
    if done >= 2:
        return {"role": "assistant", "content": FINAL_ANSWER}
    target = BLOCKED_FILE if done == 0 else ALLOWED_FILE
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": f"call_compat_{done + 1}",
                "type": "function",
                "function": {
                    "name": tool,
                    "arguments": json.dumps({"command": f"touch {target}"}),
                },
            }
        ],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "sentrook-compat-mock/1"
    log_path: str = ""
    client_id: str = ""
    client_secret: str = ""
    tool: str = "terminal"

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet stderr; the JSON log is the record
        return

    def _record(self, entry: dict[str, Any]) -> None:
        if not self.log_path:
            return
        with _log_lock, open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"method": self.command, "path": self.path, **entry}) + "\n")

    def _origin(self) -> str:
        return f"http://{self.headers.get('Host') or '127.0.0.1'}"

    def _send(self, status: int, body: Any, ctype: str = "application/json") -> None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> bytes:
        return self.rfile.read(int(self.headers.get("content-length") or 0))

    def do_GET(self) -> None:  # noqa: N802
        self._record({})
        if self.path == "/.well-known/openid-configuration":
            origin = self._origin()
            self._send(200, {"issuer": origin, "token_endpoint": f"{origin}/oauth/token"})
        elif self.path == "/healthz":
            self._send(200, {"ok": True, "version": "compat-mock", "environment": "compat"})
        elif self.path.rstrip("/") == "/v1/models":
            self._send(200, {"object": "list", "data": [{"id": "compat-mock", "object": "model"}]})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        raw = self._body()
        if self.path == "/oauth/token":
            form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
            ok = (
                form.get("client_id") == self.client_id
                and form.get("client_secret") == self.client_secret
            )
            self._record({"grant_type": form.get("grant_type"), "accepted": ok})
            if not ok:
                self._send(401, {"error": "invalid_client"})
                return
            now = int(time.time())
            token = _jwt({"sub": self.client_id, "aud": form.get("audience"), "exp": now + 1800})
            self._send(200, {"access_token": token, "token_type": "Bearer", "expires_in": 1800})
        elif self.path == "/scan":
            try:
                planir = json.loads(raw or b"{}")
            except ValueError:
                planir = None
            authed = (self.headers.get("authorization") or "").startswith("Bearer ")
            resp = scan_response(planir)
            pending = planir.get("pending_call") if isinstance(planir, dict) else None
            self._record(
                {
                    "authed": authed,
                    "tool": (pending or {}).get("tool") if isinstance(pending, dict) else None,
                    "enforced": resp.get("enforced"),
                    "body": planir,
                }
            )
            self._send(200 if authed else 401, resp if authed else {"error": "unauthorized"})
        elif self.path.rstrip("/").endswith("/chat/completions"):
            req = json.loads(raw or b"{}")
            msg = model_reply(req.get("messages") or [], self.tool)
            step = (
                msg["tool_calls"][0]["function"]["arguments"] if msg.get("tool_calls") else "answer"
            )
            self._record({"model_step": step})
            if req.get("stream"):
                self._stream(req, msg)
            else:
                self._send(200, _completion(req, msg))
        else:
            self._record({})
            self._send(404, {"error": "not found"})

    def _stream(self, req: dict[str, Any], msg: dict[str, Any]) -> None:
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.end_headers()
        base = {
            "id": "chatcmpl-compat",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
        }
        base["model"] = req.get("model") or "compat-mock"
        delta: dict[str, Any] = {"role": "assistant"}
        if msg.get("tool_calls"):
            delta["tool_calls"] = [{"index": i, **c} for i, c in enumerate(msg["tool_calls"])]
            finish = "tool_calls"
        else:
            delta["content"] = msg["content"]
            finish = "stop"
        chunks = [
            {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
            {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]},
        ]
        if (req.get("stream_options") or {}).get("include_usage"):
            chunks.append({**base, "choices": [], "usage": _usage()})
        for c in chunks:
            self.wfile.write(f"data: {json.dumps(c)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True


def _usage() -> dict[str, int]:
    return {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}


def _completion(req: dict[str, Any], msg: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "chatcmpl-compat",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.get("model") or "compat-mock",
        "choices": [
            {
                "index": 0,
                "message": msg,
                "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop",
            }
        ],
        "usage": _usage(),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8790)
    ap.add_argument("--log", required=True, help="JSON-lines request log")
    ap.add_argument("--client-id", required=True)
    ap.add_argument("--client-secret", required=True)
    ap.add_argument("--tool", default="terminal", help="the host's shell tool the model calls")
    args = ap.parse_args()
    Handler.log_path = args.log
    Handler.client_id = args.client_id
    Handler.client_secret = args.client_secret
    Handler.tool = args.tool
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
