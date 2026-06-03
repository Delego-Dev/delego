<!-- Fork the repo and open this PR from a branch in your fork. See CONTRIBUTING.md. -->

## What & why

<!-- What does this change do, and why? Link any issue. -->

## AI assistance disclosure (required)

<!-- AI-assisted PRs are welcome but get stricter review. Be specific. -->

- [ ] No AI assistance.
- [ ] AI-assisted. Tool(s) and how used: ______
- [ ] AI-generated, human-reviewed. I have read every line and am accountable for it.

## Checklist

- [ ] Forked the repo; this PR comes from a branch in my fork.
- [ ] `pytest` passes locally.
- [ ] `python examples/demo.py` still shows all eight scenarios + tamper detection.
- [ ] **Tests added/updated** for the behaviour changed (or explained why none are needed).
- [ ] Updated `README.md` and `CHANGELOG.md` for any behaviour change.
- [ ] I have **not weakened any design invariant** (see `CONTRIBUTING.md` / `ARCHITECTURE.md`):
  no LLM in the authorization path; no credential custody; fail-closed; approvals
  bound to fingerprint + intent and single-use; append-only signed audit chain;
  fixed evaluation order.

## Protocol / spec impact

- [ ] No normative/protocol behaviour changed.
- [ ] Normative behaviour changed — the [wire spec](https://github.com/Delego-Dev/specification)
  and its CTK vectors are updated (or a linked spec PR does so), and
  `__protocol_version__` stays ≤ the spec version.
