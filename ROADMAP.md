# Roadmap

RunReconcile is an early-stage, maintainer-led project. This roadmap records
real intended work, not adoption claims or fixed delivery promises. Priorities
may change when public usage reports reveal a more important reliability,
privacy, or compatibility problem.

## Current 0.1.x goals

- Keep the contract and receipt schemas strict and backward compatible.
- Validate every supported Python release on Linux and macOS.
- Make installation, packaging, and the complete local demo reproducible.
- Publish small, sanitized maintainer dogfood case studies that show both
  accepted runs and failures RunReconcile actually detected.
- Turn reproducible user feedback into narrowly scoped issues and releases.

## Planned investigations

### GitHub Actions integration

Document a minimal workflow that retains the baseline digest separately,
publishes only the public-safe receipt, and fails the job on a non-accepted
verdict. Acceptance requires a working example repository and a threat-model
review of artifact retention.

### Windows support

Design a Windows traversal implementation that fails closed around junctions
and reparse points and provides semantics equivalent to POSIX descriptor-
relative traversal. Windows support will not be claimed until adversarial path
tests pass on real Windows runners.

### Optional receipt authenticity

Explore an external signing interface for users who need origin authenticity in
addition to the current completion digest. Any design must keep private
baselines local, avoid hidden network behavior, and clearly separate integrity
from identity.

### Scale and ergonomics

Measure large directory trees, improve diagnostics without leaking private path
names, and reduce setup friction without weakening byte, entry, depth, or
stability limits.

## Non-goals

RunReconcile will not become a workflow runner, shell wrapper, sandbox, malware
scanner, runtime write tracer, hosted telemetry service, or proof that a
specific process caused a change.

## How work is selected

Security and privacy regressions come first, followed by correctness defects,
supported-platform compatibility, and feedback backed by a reproducible use
case. See [`GOVERNANCE.md`](GOVERNANCE.md) and
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the decision and contribution process.
