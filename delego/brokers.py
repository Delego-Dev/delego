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


@runtime_checkable
class BrokerAdapter(Protocol):
    name: str

    def execute(self, action: ProposedAction) -> dict[str, Any]:
        ...


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
        record = {
            "broker": self.name,
            "would_send": action.summary(),
            "note": "stub: no credential injected, no upstream request made",
        }
        self.sent.append(record)
        return {"status": "simulated", "detail": record}


class HTTPProxyBroker:
    """Sketch of a real adapter — NOT wired up in v0.1.

    In production this points at a running credential broker (for example
    OneCLI's gateway on ``localhost:10255``, or an Agent Vault proxy). The broker
    matches a credential by host/path, injects it, and forwards the request. The
    firewall has already decided the action is allowed; this adapter only carries
    it through the component that actually holds the secret.
    """

    name = "http_proxy"

    def __init__(self, proxy_url: str) -> None:
        self.proxy_url = proxy_url

    def execute(self, action: ProposedAction) -> dict[str, Any]:
        raise NotImplementedError(
            "Wire this to your credential broker. Route the request through "
            f"{self.proxy_url!r}; the broker injects the credential and forwards "
            "upstream. The firewall has already authorised this action."
        )
