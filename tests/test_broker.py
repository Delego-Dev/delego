"""HTTPProxyBroker: forwarding an authorised action to a credential gateway.

A tiny in-process HTTP server stands in for the gateway (the component that would
hold the secret and call upstream). These tests prove the broker forwards the
action — including its fingerprint, for gateway-side re-verification — and surfaces
the gateway's response without raising on an error status.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from delego import ProposedAction, build_firewall
from delego.brokers import HTTPProxyBroker
from delego.config import Paths


class _Gateway(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(n))
        if body["url"].endswith("/fail"):
            self.send_response(502)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "upstream refused"}')
            return
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        # Simulate: gateway injected a credential and called upstream, echoing
        # back what it received so the test can assert on the forwarded payload.
        self.wfile.write(json.dumps({"injected": True, "forwarded": body}).encode())

    def log_message(self, *_):  # silence the test server
        pass


@pytest.fixture
def gateway():
    srv = HTTPServer(("127.0.0.1", 0), _Gateway)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/inject"
    srv.shutdown()


def test_forwards_action_and_fingerprint_and_returns_response(gateway):
    broker = HTTPProxyBroker(gateway)
    action = ProposedAction("read my data", "GET", "https://api.example.com/x", {"k": "v"})

    out = broker.execute(action)

    assert out["broker"] == "http_proxy"
    assert out["gateway_status"] == 200
    assert out["response"]["injected"] is True
    fwd = out["response"]["forwarded"]
    assert fwd["method"] == "GET"
    assert fwd["url"] == "https://api.example.com/x"
    assert fwd["params"] == {"k": "v"}
    # the action fingerprint + intent travel with it, so a gateway can re-verify
    assert fwd["action_fingerprint"] == action.fingerprint
    assert fwd["intent_hash"] == action.intent_hash


def test_gateway_error_is_returned_not_raised(gateway):
    broker = HTTPProxyBroker(gateway)
    out = broker.execute(ProposedAction("x", "GET", "https://api.example.com/fail", {}))
    assert out["gateway_status"] == 502
    assert out["response"]["error"] == "upstream refused"


_POLICY = """
version: 1
default: deny
rules:
  - name: read
    decision: allow
    match: { method: GET, host: api.example.com, path: /** }
"""


def test_firewall_allow_executes_through_the_gateway(tmp_path, gateway):
    home = tmp_path / "home"
    home.mkdir()
    (home / "policy.yaml").write_text(_POLICY, encoding="utf-8")
    fw = build_firewall(Paths.resolve(home), broker=HTTPProxyBroker(gateway))

    d = fw.propose(ProposedAction("read my data", "GET", "https://api.example.com/x", {}))

    assert d.outcome == "allow" and d.executed is True
    assert d.result["response"]["injected"] is True
    assert fw.audit.verify()[0] is True


def test_firewall_forwards_a_verifiable_token_to_the_gateway(tmp_path, gateway):
    # With the §9 profile on, the broker forwards the minted token; a separated
    # gateway can verify it and re-check the fingerprint of what it will send.
    from delego import require_fingerprint, verify_token

    home = tmp_path / "home"
    home.mkdir()
    (home / "policy.yaml").write_text(_POLICY, encoding="utf-8")
    fw = build_firewall(
        Paths.resolve(home),
        broker=HTTPProxyBroker(gateway),
        mint_tokens=True,
        token_audience="broker:default",
    )

    action = ProposedAction("read my data", "GET", "https://api.example.com/x", {})
    d = fw.propose(action)

    assert d.outcome == "allow" and d.token is not None
    forwarded = d.result["response"]["forwarded"]
    assert forwarded["authorization_token"] == d.token  # reached the gateway

    # The gateway verifies the token and binds it to the exact action (step 5).
    claims = verify_token(d.token, public_key=fw.token_issuer.public_key, audience="broker:default")
    require_fingerprint(claims, action)
