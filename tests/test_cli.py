"""CLI surface: the human consent moment and head-anchor ergonomics (0.3.1)."""

from __future__ import annotations

from click.testing import CliRunner

from delego import ProposedAction
from delego.cli import cli


def _home_of(firewall) -> str:
    return str(firewall.audit.path.parent)


def _small_order() -> ProposedAction:
    return ProposedAction(
        instruction="place a small order",
        method="POST",
        url="https://api.example.com/orders",
        params={"amount": 2400, "currency": "USD", "destination": "internal"},
    )


def test_approve_echoes_what_was_approved(firewall):
    d = firewall.propose(_small_order())
    out = CliRunner().invoke(cli, ["--home", _home_of(firewall), "approve", d.approval_id, "--as", "koishore"])
    assert out.exit_code == 0
    # The approver sees the action and the instruction, not just an id.
    assert f"{d.approval_id}: approved" in out.output
    assert "POST api.example.com/orders" in out.output
    assert "place a small order" in out.output


def test_verify_anchor_file_round_trip_and_rollback_detection(firewall, tmp_path):
    firewall.propose(
        ProposedAction(
            instruction="read my account details",
            method="GET",
            url="https://api.example.com/accounts/me",
        )
    )
    anchor = tmp_path / "anchor"
    runner = CliRunner()
    home = _home_of(firewall)

    # First run: clean verify, anchor written.
    first = runner.invoke(cli, ["--home", home, "verify", "--anchor-file", str(anchor)])
    assert first.exit_code == 0
    assert "Anchor updated" in first.output
    head = anchor.read_text().strip()
    assert head and ":" in head

    # Second run: checked against the stored anchor.
    second = runner.invoke(cli, ["--home", home, "verify", "--anchor-file", str(anchor)])
    assert second.exit_code == 0
    assert "Head anchor matches" in second.output

    # Truncate the ledger: the anchor catches the rollback chaining can't.
    log = firewall.audit.path
    log.write_text("", encoding="utf-8")
    third = runner.invoke(cli, ["--home", home, "verify", "--anchor-file", str(anchor)])
    assert third.exit_code == 1
    assert "truncated or rolled back" in third.output
    # A failed verify must NOT advance the anchor.
    assert anchor.read_text().strip() == head


def test_verify_rejects_combining_anchor_file_and_expected_head(firewall, tmp_path):
    out = CliRunner().invoke(
        cli,
        ["--home", _home_of(firewall), "verify", "--anchor-file", str(tmp_path / "a"), "--expected-head", "0:ff"],
    )
    assert out.exit_code != 0
    assert "not both" in out.output
