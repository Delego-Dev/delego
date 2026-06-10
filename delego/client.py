"""Client for the single-writer daemon (:mod:`delego.daemon`).

A thin, dependency-free wrapper over the Unix-domain-socket, line-delimited JSON
protocol. Each call opens a short-lived connection, sends one request, reads one
response. When a daemon is running, the CLI (and, later, the MCP server) route
their operations here so the ledger keeps a single writer.
"""

from __future__ import annotations

import json
import socket
from typing import Any, Optional


class DaemonError(RuntimeError):
    """The daemon returned an error, or could not be reached."""


def daemon_running(socket_path) -> bool:
    """True if a live daemon answers ``ping`` on ``socket_path``."""
    try:
        return DaemonClient(socket_path).ping()
    except DaemonError:
        return False


class DaemonClient:
    """Talk to a running ``delego daemon`` over its Unix socket."""

    def __init__(self, socket_path, timeout: float = 30.0) -> None:
        self.socket_path = str(socket_path)
        self.timeout = timeout

    def _call(self, op: str, **args) -> Any:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.socket_path)
        except OSError as e:
            raise DaemonError(f"no delego daemon at {self.socket_path}: {e}") from e
        try:
            s.sendall((json.dumps({"op": op, **args}) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    raise DaemonError("daemon closed the connection without responding")
                buf += chunk
        finally:
            s.close()
        resp = json.loads(buf.split(b"\n", 1)[0])
        if not resp.get("ok"):
            raise DaemonError(resp.get("error", "unknown daemon error"))
        return resp["result"]

    # -- ops ------------------------------------------------------------------ #
    def ping(self) -> bool:
        try:
            return bool(self._call("ping").get("ok"))
        except DaemonError:
            return False

    def propose(self, instruction: str, method: str, url: str, params: Optional[dict] = None) -> dict:
        return self._call("propose", instruction=instruction, method=method, url=url, params=params or {})

    def resolve(self, approval_id: str, instruction: str, method: str, url: str, params: Optional[dict] = None) -> dict:
        return self._call(
            "resolve", approval_id=approval_id, instruction=instruction, method=method, url=url, params=params or {}
        )

    def decide(self, approval_id: str, approved: bool, approver: str = "cli") -> Optional[dict]:
        return self._call("decide", approval_id=approval_id, approved=approved, approver=approver)

    def pending(self) -> list[dict]:
        return self._call("pending")

    def audit_tail(self, lines: int = 20) -> list[dict]:
        return self._call("audit_tail", lines=lines)

    def verify(self, expected_head: Optional[tuple] = None) -> dict:
        return self._call("verify", expected_head=list(expected_head) if expected_head else None)

    def policy(self) -> dict:
        return self._call("policy")
