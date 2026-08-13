# Governance and maintenance

RunReconcile currently has one primary maintainer:

- [Neo Chen (`@chown8872-afk`)](https://github.com/chown8872-afk) — project
  direction, issue triage, pull request review, releases, and security response.

This is intentionally a truthful single-maintainer record. It does not imply a
larger team or external adoption.

## Decisions

Small fixes are decided in their pull requests. Contract, receipt, threat-model,
or compatibility changes should start with a public issue so alternatives and
migration impact can be recorded. Security-sensitive details use the private
reporting channel in [`SECURITY.md`](SECURITY.md) until coordinated disclosure
is safe.

The maintainer makes final decisions using these priorities:

1. documented security and privacy invariants;
2. fail-closed correctness and reproducible evidence;
3. backward compatibility for the current schema version;
4. supported-platform reliability; and
5. usability that does not weaken the first four priorities.

## Reviews and releases

Changes should be submitted through pull requests, pass all required CI jobs,
and include tests and documentation appropriate to their risk. The maintainer
may request independent review for path traversal, receipt disclosure, or
contract-schema changes.

Releases follow semantic versioning and are documented in
[`CHANGELOG.md`](CHANGELOG.md). Tags are not moved after publication. Build
artifacts are produced by the public release workflow; PyPI publication uses
trusted publishing rather than a long-lived repository token.

## Support expectations

Maintenance is best effort and has no response-time guarantee. Reproducible
security, privacy, and correctness reports receive priority. Public issue
status, pull request review, and release history are the source of truth for
project activity.

## Adding maintainers

Additional maintainers may be invited after sustained, high-quality
contributions and demonstrated care for the threat model. Access will be scoped
to actual responsibilities and recorded here; no role will be listed solely for
appearance or program eligibility.
