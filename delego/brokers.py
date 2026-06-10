"""Broker adapters: where the *authorised* action actually gets executed.

This firewall does not hold credentials. Once it has authorised an action, it
hands the action to a broker that injects the user's credential and forwards the
request upstream. The agent — and this firewall — never see the secret.

That is the existing, crowded layer (Infisical Agent Vault, OneCLI, Browser Use,
etc.). The point of keeping it behind a thin ``BrokerAdapter`` interface is that
you ride that layer instead of rebuilding it: swap ``NullBroker`` for a real
adapter and the decision/audit logic above is unchanged.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from .models import ProposedAction


class BrokerRefusal(ValueError):
    """A broker refused to execute because the action carried data the firewall
    never authorised (e.g. a URL fragment outside the fingerprint, spec §4.2).

    This is a fail-closed guard, not an upstream/transport error: the request is
    *not* sent. It subclasses ``ValueError`` so existing ``except ValueError``
    handlers keep treating it as a bad request.
    """


@runtime_checkable
class BrokerAdapter(Protocol):
    """Executes an *already-authorised* action — and nothing more.

    **Execution contract (NORMATIVE, spec §4.2).** A broker MUST execute only the
    action the firewall fingerprinted: ``method`` + ``host`` + ``path`` +
    canonicalized ``query`` + ``params``. Since protocol 0.3 the URL's query
    string is folded into the fingerprint preimage, so the *decision* — not
    merely the broker — is bound to it: ``/orders?to=me`` and
    ``/orders?to=attacker`` carry different fingerprints, and a broker may
    forward the query of an authorised action. A broker MUST NOT forward any
    channel the fingerprint does not represent — the URL's **#fragment**, or
    request **headers** derived from the agent's input.

    Concretely a broker MUST request :attr:`ProposedAction.fingerprinted_url`
    (scheme+host+path+query) and carry ``params`` as the action model intends,
    and MUST refuse — raise :class:`BrokerRefusal`, never silently strip — when
    ``action.url`` carries a fragment (:attr:`ProposedAction.has_fragment`)
    that the fingerprint does not represent.
    """

    name: str

    def execute(self, action: ProposedAction) -> dict[str, Any]:
        ...


def _require_no_unauthorised_fragment(action: ProposedAction) -> None:
    """Fail closed if ``action.url`` carries a ``#fragment``.

    The fragment is outside the fingerprint preimage (spec §4.2), so a value
    riding it was never authorised. Rather than silently drop it (which would
    hide that the agent attached data the decision never saw), a broker refuses
    outright.
    """
    if action.has_fragment:
        raise BrokerRefusal(
            "broker refuses to execute: action.url carries a #fragment, which "
            "is not part of the fingerprint (method+host+path+query+params) and "
            "was therefore never authorised (spec §4.2). Move any decision-"
            "relevant value into params so it is fingerprinted and audited. "
            "Offending url: " + action.url
        )


class NullBroker:
    """Default stand-in broker. Holds NO credentials and makes NO real request.

    It records what *would* have been sent so the full decision -> execution
    loop is observable end to end. Use it for local development, demos, and
    tests; replace it with a real adapter for anything that touches a live
    service.
    """

    name = "null"

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def execute(self, action: ProposedAction) -> dict[str, Any]:
        # Honour the execution contract even when simulating: a stray fragment
        # is unauthorised data regardless of whether a real request is made.
        _require_no_unauthorised_fragment(action)
        record = {
            "broker": self.name,
            "would_send": action.summary(),
            "note": "stub: no credential injected, no upstream request made",
        }
        self.sent.append(record)
        return {"status": "simulated", "detail": record}


class HTTPProxyBroker:
    """Forward an authorised action to an external credential **gateway**.

    This is the real, dependency-light way to wire delego to a credential broker
    that holds the secret — OneCLI's local gateway, an Agent Vault proxy, or your
    own. The gateway matches a credential by host/path, injects it, forwards the
    request upstream, and returns the response. delego only carries the
    already-authorised action across to that component.

    **Trust model (invariant: delego holds no credentials).** The upstream secret
    lives in the *gateway*, never here. ``gateway_headers`` authenticate delego to
    the *local gateway* (e.g. a loopback token) — they are **not** the brokered
    upstream credential, and MUST NOT be one.

    It POSTs ``{method, url, params, intent_hash, action_fingerprint}`` as JSON to
    ``gateway_url``. The forwarded ``url`` is the **fingerprinted** URL
    (scheme+host+path+query): since protocol 0.3 the query is folded into the
    fingerprint, so it is part of the authorised action and travels with it. Per
    the :class:`BrokerAdapter` contract (spec §4.2) the broker never forwards a
    ``#fragment`` — the fingerprint does not represent it — and refuses
    (:class:`BrokerRefusal`) instead. Sending the fingerprint lets a gateway
    re-verify the action it is about to perform (and aligns with the forthcoming
    signed authorization token, spec §9). The gateway's JSON response is returned
    under ``response``.
    """

    name = "http_proxy"

    def __init__(
        self,
        gateway_url: str,
        *,
        timeout: float = 15.0,
        gateway_headers: dict[str, str] | None = None,
    ) -> None:
        self.gateway_url = gateway_url
        self.timeout = timeout
        self._headers = {"content-type": "application/json", **(gateway_headers or {})}

    def execute(self, action: ProposedAction) -> dict[str, Any]:
        import json
        import urllib.error
        import urllib.request

        # Fail closed before building the request: a #fragment on action.url is
        # data outside the fingerprint preimage (spec §4.2).
        _require_no_unauthorised_fragment(action)

        payload = json.dumps(
            {
                "method": action.method.upper(),
                # Forward only the fingerprinted URL (scheme+host+path+query);
                # the fragment is never represented in the fingerprint, so it is
                # never sent.
                "url": action.fingerprinted_url,
                "params": action.params,
                "intent_hash": action.intent_hash,
                "action_fingerprint": action.fingerprint,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            self.gateway_url, data=payload, method="POST", headers=self._headers
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:  # gateway refused / upstream error
            status = e.code
            body = e.read().decode("utf-8", "replace")
        try:
            parsed: Any = json.loads(body) if body else None
        except json.JSONDecodeError:
            parsed = {"raw": body[:1000]}
        return {
            "broker": self.name,
            "gateway": self.gateway_url,
            "gateway_status": status,
            "response": parsed,
        }
