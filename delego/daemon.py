"""The single-writer daemon — one process that owns the ledger.

delego's file-backed state is corruption-safe under concurrent writers (an OS
file lock, since 0.2.1), but a `rate_limit` is *exact* only when the
count→decide→execute→append sequence is serialized through a single writer
(spec §5 consistency class, §11). On one host the 0.3.0 transaction lock gives
that — at the cost of holding the file lock through the broker call, and only
among processes sharing the same home. The daemon is the general answer: a
long-running process that is the **sole** owner of the `Firewall`, so every
client (CLI, agents, other hosts later) routes its operations through it and the
ledger has exactly one writer.

Design: the daemon *is* the firewall, exposed over a Unix domain socket with a
line-delimited JSON protocol. One lock serializes every operation, so the
guarantee is strict single-writer regardless of how many clients connect. The
broker (and any credential it holds) lives in the daemon process — the same
trust as running the firewall yourself.

Wire protocol (one JSON object per line, request then response):

    → {"op": "propose", "instruction": ..., "method": ..., "url": ..., "params": {...}}
    ← {"ok": true, "result": {...decision...}}
    ← {"ok": false, "error": "..."}

Ops: ``ping``, ``propose``, ``resolve``, ``pending``, ``policy``,
``audit_tail``, ``verify``, ``decide`` (human approve/deny).
"""

from __future__ import annotations

import json
import os
import signal
import socket
import socketserver
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .config import Paths, build_firewall
from .models import ProposedAction

PROTOCOL = 1

# The daemon uses Unix domain sockets; absent on Windows. Guard so importing
# delego never fails there — ``serve`` raises a clear error instead.
_HAS_UNIX = hasattr(socket, "AF_UNIX")


def _decision_dict(decision) -> dict[str, Any]:
    d = asdict(decision)
    d["result"] = decision.result
    return d


class _Handler(socketserver.StreamRequestHandler):
    """One connection: read newline-delimited JSON requests, answer each.

    All firewall access goes through ``server.dispatch``, which holds the
    server's single write lock — so concurrent connections are serialized into
    one logical writer."""

    def handle(self) -> None:
        for raw in self.rfile:
            line = raw.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                if not isinstance(req, dict) or "op" not in req:
                    raise ValueError("each request must be a JSON object with an 'op'")
                result = self.server.dispatch(req)
                resp = {"ok": True, "result": result}
            except Exception as e:  # never let one bad request kill the connection
                resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            self.wfile.write((json.dumps(resp) + "\n").encode("utf-8"))
            self.wfile.flush()


# Base class only where Unix sockets exist; on Windows ``serve`` errors before
# any instance is built, so this fallback is never instantiated.
_UnixServerBase = socketserver.ThreadingUnixStreamServer if _HAS_UNIX else object


class _Server(_UnixServerBase):
    daemon_threads = True
    allow_reuse_address = True
    # Hold a deep listen backlog: many clients may connect at once (the default
    # of 5 would refuse the rest with ECONNREFUSED under contention).
    request_queue_size = 128

    def __init__(self, socket_path: str, firewall) -> None:
        super().__init__(socket_path, _Handler)
        self.firewall = firewall
        # The whole point: one writer. Every mutating op (and, for simplicity and
        # read-consistency, every read) runs under this lock.
        self._lock = threading.Lock()

    # -- dispatch (under the single write lock) -------------------------------- #
    def dispatch(self, req: dict) -> Any:
        op = req["op"]
        with self._lock:
            fw = self.firewall
            if op == "ping":
                return {"protocol": PROTOCOL, "ok": True}
            if op == "propose":
                return _decision_dict(fw.propose(self._action(req)))
            if op == "resolve":
                return _decision_dict(fw.resolve(req["approval_id"], self._action(req)))
            if op == "decide":
                rec = fw.approvals.decide(req["approval_id"], bool(req["approved"]), req.get("approver", "daemon"))
                return rec  # None → unknown id (client maps to a 404-style error)
            if op == "pending":
                return fw.approvals.pending()
            if op == "audit_tail":
                return fw.audit.tail(int(req.get("lines", 20)))
            if op == "verify":
                head = req.get("expected_head")
                ok, problems = fw.audit.verify(expected_head=tuple(head) if head else None)
                return {"valid": ok, "problems": problems}
            if op == "policy":
                p = fw.policy
                return {
                    "version": p.version,
                    "default": p.default,
                    "forbidden": [{"name": r.name, "match": r.match} for r in p.forbidden],
                    "rules": [
                        {"name": r.name, "decision": r.decision, "match": r.match, "constraints": r.constraints}
                        for r in p.rules
                    ],
                }
            raise ValueError(f"unknown op {op!r}")

    @staticmethod
    def _action(req: dict) -> ProposedAction:
        return ProposedAction(req["instruction"], req["method"], req["url"], req.get("params", {}))


def _probe(socket_path: str) -> bool:
    """True if a live daemon is already answering on ``socket_path``."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect(socket_path)
        s.sendall(b'{"op":"ping"}\n')
        return b'"ok"' in s.recv(256)
    except OSError:
        return False
    finally:
        s.close()


def serve(
    paths: Paths,
    *,
    broker=None,
    mint_tokens: bool = False,
    token_audience: str = "broker:default",
    ready: "threading.Event | None" = None,
) -> None:
    """Run the single-writer daemon until SIGINT/SIGTERM (blocking).

    Refuses to start if a live daemon already owns the socket — two writers is
    exactly what this exists to prevent. ``ready`` (if given) is set once the
    server is listening, for tests/embedding.
    """
    if not _HAS_UNIX:
        raise RuntimeError(
            "the delego daemon requires Unix domain sockets, which are not "
            "available on this platform"
        )
    socket_path = str(paths.socket)
    if os.path.exists(socket_path):
        if _probe(socket_path):
            raise RuntimeError(f"a delego daemon is already running on {socket_path}")
        os.unlink(socket_path)  # stale socket from a crashed daemon

    paths.home.mkdir(parents=True, exist_ok=True)
    firewall = build_firewall(paths, broker=broker, mint_tokens=mint_tokens, token_audience=token_audience)
    server = _Server(socket_path, firewall)
    os.chmod(socket_path, 0o600)  # owner-only

    def _shutdown(*_):
        # shutdown() must run off the serving thread; the signal handler just
        # spawns it so serve_forever() returns and we clean up the socket.
        threading.Thread(target=server.shutdown, daemon=True).start()

    # Signal handlers can only be installed from the main thread; when the daemon
    # is embedded in a background thread (tests, in-process hosts) the caller owns
    # shutdown via server lifetime instead.
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)

    if ready is not None:
        ready.set()
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if os.path.exists(socket_path):
            os.unlink(socket_path)
