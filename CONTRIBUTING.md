# Contributing to RunReconcile

Thank you for helping improve RunReconcile. Small, focused changes with explicit
security and privacy reasoning are easiest to review.

## Project invariants

Changes must preserve these properties unless a versioned design discussion
explicitly changes them:

- The verifier never executes the observed automation.
- Contracts remain declarative and contain no commands, hooks, imports, or
  interpolation that can become execution.
- Runtime behavior remains local: no network calls, telemetry, analytics, or
  update checks.
- Observation is final-state only and must not claim process attribution or
  transient-write coverage.
- Unsafe, unstable, oversized, ambiguous, or unsupported inputs fail closed.
- Each check path is covered by exactly one non-overlapping watch, and freshness
  means content change rather than a timestamp or permission touch.
- Public receipts omit raw asserted values, absolute paths, unexpected path
  names, and delivery receipt IDs.
- Baselines are treated as private artifacts.
- Receipt consumers require the completion marker and verify its JSON digest.
- Python 3.9 through 3.12 on Linux and macOS remain supported for the 0.1.x line.

Read [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`PRIVACY.md`](PRIVACY.md) before
changing contract parsing, path handling, snapshots, checks, verdicts, or
receipt fields.

## Development setup

```console
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m unittest discover -s tests -v
```

The test suite uses `unittest` and does not require a network service.

You can exercise the packaged entry point with:

```console
runreconcile --version
runreconcile validate --contract examples/runreconcile.toml
```

## Making a change

1. Open an issue for behavior or schema changes so compatibility and threat
   model implications can be discussed first.
2. Add or update tests for success, failure, and privacy behavior.
3. Prefer explicit validation and stable public error codes over leaking raw
   exception text into receipts.
4. Keep file handling portable and test symlink behavior conditionally where
   the platform requires it.
5. Update README, threat model, privacy notes, and changelog when public behavior
   changes.
6. Run the full test suite on a clean tree.

When adding a check type, define its strict allowlisted schema, its path coverage
rules, byte limits, stable result codes, required evidence, and public evidence
separately. Do not serialize actual or expected values merely for debugging.

## Pull request checklist

- [ ] The change is narrowly scoped and backward compatibility is explained.
- [ ] Tests cover malformed and adversarial input, not only the happy path.
- [ ] `python -m unittest discover -s tests -v` passes.
- [ ] No command-execution, network, or telemetry path was introduced.
- [ ] New receipt fields were reviewed for public disclosure risk.
- [ ] Baseline and path-containment implications were reviewed.
- [ ] Freshness behavior cannot be satisfied by metadata-only changes.
- [ ] Receipt publication remains exclusive and completion-marker based.
- [ ] Documentation and `CHANGELOG.md` are current.
- [ ] No generated baseline, receipt, secret, or example output is committed.

## Security reports

Do not open a public pull request containing an undisclosed vulnerability or
real sensitive data. Follow [`SECURITY.md`](SECURITY.md) instead.

## Conduct

Be respectful, specific, and evidence-based. Harassment, discrimination, and
publication of another person's private data are not acceptable.
