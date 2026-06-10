"""The single-writer daemon: round-trip ops and cross-client rate-limit exactness.

The headline is ``test_rate_limit_exact_across_concurrent_clients`` — many
clients proposing the same rate-limited action through one daemon get exactly
``max`` allows. That is the guarantee the file lock alone can't give across
separate processes, and the reason the daemon exists.
"""

from __future__ import annotations

import concurrent.futures as cf
import socket
import threading

import pytest

from delego import DaemonClient, daemon_running, serve
from delego.config import Paths

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="daemon needs Unix domain sockets"
)

_RATE_LIMITED = """
version: 1
default: deny
rules:
  - name: read
    decision: allow
    match: { method: GET, host: api.example.com, path: /data }
    constraints:
      rate_limit: { max: 3, per: hour }
  - name: place-order
    decision: needs_approval
    match: { method: POST, host: api.example.com, path: /orders }
"""


@pytest.fixture
def daemon(tmp_path):
    """A running daemon on an isolated home; yields its DaemonClient."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "policy.yaml").write_text(_RATE_LIMITED, encoding="utf-8")
    paths = Paths.resolve(str(home))
    ready = threading.Event()
    server_thread = threading.Thread(target=serve, args=(paths,), kwargs={"ready": ready}, daemon=True)
    server_thread.start()
    assert ready.wait(5), "daemon did not start"
    yield DaemonClient(paths.socket), paths
    # daemon thread is a daemon=True thread on a throwaway tmp home; it dies with
    # the test process. (serve installs no signal handlers off the main thread.)


def test_ping_and_daemon_running(daemon):
    client, paths = daemon
    assert client.ping() is True
    assert daemon_running(paths.socket) is True


def test_propose_allow_and_policy_round_trip(daemon):
    client, _ = daemon
    assert client.policy()["default"] == "deny"
    d = client.propose("read data", "GET", "https://api.example.com/data")
    assert d["outcome"] == "allow" and d["executed"] is True


def test_rate_limit_exact_across_concurrent_clients(daemon):
    client, _ = daemon

    def propose(_i):
        return client.propose("read data", "GET", "https://api.example.com/data")["outcome"]

    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        outcomes = list(ex.map(propose, range(16)))

    # Exactly the cap, regardless of concurrency — the single-writer guarantee.
    assert outcomes.count("allow") == 3
    assert outcomes.count("deny") == 13
    assert client.verify()["valid"] is True


def test_full_approval_loop_over_the_socket(daemon):
    client, _ = daemon
    order = dict(instruction="place a small order", method="POST", url="https://api.example.com/orders",
                 params={"amount": 2400, "currency": "USD", "destination": "internal"})
    parked = client.propose(**order)
    assert parked["outcome"] == "needs_approval"
    aid = parked["approval_id"]
    assert [p["id"] for p in client.pending()] == [aid]

    # human approves through the daemon, then the action releases once
    assert client.decide(aid, approved=True, approver="alice")["status"] == "approved"
    released = client.resolve(aid, **order)
    assert released["outcome"] == "allow" and released["executed"] is True
    # single-use: replay denied
    assert client.resolve(aid, **order)["outcome"] == "deny"
    # unknown id → None (the CLI maps that to a not-found)
    assert client.decide("apr_nope", approved=True) is None


def test_audit_tail_and_verify(daemon):
    client, _ = daemon
    client.propose("read data", "GET", "https://api.example.com/data")
    tail = client.audit_tail(10)
    assert tail and tail[-1]["outcome"] == "allow"
    assert client.verify()["valid"] is True


def test_second_daemon_refuses_to_start(daemon, tmp_path):
    _, paths = daemon
    # A second serve() on the same live socket must refuse (two writers is the
    # one thing the daemon exists to prevent).
    with pytest.raises(RuntimeError, match="already running"):
        serve(paths)


def test_bad_request_does_not_kill_the_connection(daemon):
    _, paths = daemon
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(str(paths.socket))
    s.sendall(b"not json\n")
    resp1 = s.recv(4096)
    assert b'"ok": false' in resp1
    # same connection still serves a valid request
    s.sendall(b'{"op":"ping"}\n')
    assert b'"ok": true' in s.recv(4096)
    s.close()
