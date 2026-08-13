# Security policy

## Supported versions

RunReconcile is currently an early-stage project. Security fixes are provided
for the latest `0.1.x` release line only.

| Version | Supported |
|---|---|
| `0.1.x` | Yes |
| Older or unreleased snapshots | No |

## Reporting a vulnerability

Please use the repository's **Security → Report a vulnerability** flow so the
report is handled privately. Include:

- the affected version and operating system;
- the smallest contract and filesystem layout that reproduces the issue;
- the command invoked and the observed result;
- the security or privacy property you expected; and
- a proof of concept that does not contain third-party secrets or personal data.

If private vulnerability reporting is unavailable, open a public issue asking
the maintainers to establish a private contact channel. Do not include exploit
details, private baselines, sensitive paths, raw artifact values, or credentials
in that issue.

Do not test against systems or data you do not own or have permission to use.
Reports about command execution are especially important because the contract
and verifier are intentionally non-executable. Reports about path containment,
symlink handling, receipt disclosure, unstable-file acceptance, or verdict
integrity are also in scope.

## Scope notes

The following documented limitations are not vulnerabilities by themselves:

- transient writes between snapshots are not observed;
- final-state changes are not attributed to a process;
- only declared watch roots and checks are covered;
- baseline snapshots are private artifacts and contain relative names and
  hashes;
- receipts are hashed but not digitally signed; and
- contract-authored IDs, labels, run IDs, and opt-in artifact digests appear in
  public receipts.

An implementation that violates the documented containment, fail-closed, or
receipt-minimization behavior is in scope. See [`THREAT_MODEL.md`](THREAT_MODEL.md)
and [`PRIVACY.md`](PRIVACY.md) for the complete claims.

## Coordinated disclosure

Please allow maintainers a reasonable opportunity to reproduce, fix, and
release before public disclosure. Maintainers will credit reporters when desired
and when doing so is safe.
