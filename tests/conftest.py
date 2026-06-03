"""Shared fixtures for the delego test suite.

Every test runs against its **own** firewall on a throwaway home directory
(fresh signing keys, an empty audit ledger, an empty approval queue). That
isolation is what makes the suite deterministic: nothing leaks the audit chain
or rate-limit counters from one test into the next. This mirrors how
``examples/demo.py`` builds a firewall in a ``tempfile.mkdtemp`` home.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from delego import build_firewall
from delego.config import Paths

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_EXAMPLE = REPO_ROOT / "policy.example.yaml"


@pytest.fixture
def make_firewall(tmp_path):
    """Factory building an isolated :class:`~delego.engine.Firewall`.

    Call with no arguments to use the shipped ``policy.example.yaml`` (what the
    demo uses), or pass a YAML string to install a custom policy for the test.
    Each call gets its own home dir, so a test may build several independent
    firewalls without sharing state.
    """

    count = 0

    def _make(policy_yaml: str | None = None):
        nonlocal count
        home = tmp_path / f"home{count}"
        count += 1
        home.mkdir()
        policy_path = home / "policy.yaml"
        if policy_yaml is None:
            shutil.copy(POLICY_EXAMPLE, policy_path)
        else:
            policy_path.write_text(policy_yaml, encoding="utf-8")
        return build_firewall(Paths.resolve(home))

    return _make


@pytest.fixture
def firewall(make_firewall):
    """An isolated firewall loaded with the shipped example policy."""
    return make_firewall()
