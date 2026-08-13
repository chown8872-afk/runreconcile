## What changed

Describe the smallest complete change and the user or maintainer impact.

## Why

Link the issue or reproducible use case this addresses.

## Security and privacy review

- [ ] No command execution, network, telemetry, or hidden plugin path was added.
- [ ] Path containment, baseline privacy, receipt disclosure, and fail-closed behavior were reviewed where relevant.
- [ ] Contract or receipt schema compatibility is explained where relevant.

## Verification

- [ ] Tests cover success and failure behavior.
- [ ] `python -m unittest discover -s tests -v` passes.
- [ ] `./scripts/run_demo.sh` produces `ACCEPTED`.
- [ ] Documentation and `CHANGELOG.md` are current.
- [ ] No generated baseline, secret, or sensitive path was committed.
