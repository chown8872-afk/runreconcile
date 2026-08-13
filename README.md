# RunReconcile

[![CI](https://github.com/chown8872-afk/runreconcile/actions/workflows/ci.yml/badge.svg)](https://github.com/chown8872-afk/runreconcile/actions/workflows/ci.yml)
[![CodeQL](https://github.com/chown8872-afk/runreconcile/actions/workflows/codeql.yml/badge.svg)](https://github.com/chown8872-afk/runreconcile/actions/workflows/codeql.yml)
[![GitHub release](https://img.shields.io/github/v/release/chown8872-afk/runreconcile?include_prereleases)](https://github.com/chown8872-afk/runreconcile/releases)
[![Python 3.9–3.14](https://img.shields.io/badge/python-3.9%E2%80%933.14-blue)](https://github.com/chown8872-afk/runreconcile/actions/workflows/ci.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**A local-only post-run automation verifier for final-state receipts and write
boundaries.**

RunReconcile produces a public-safe receipt for the final state left by an
automation. It observes the declared workspace before and after a run, applies
strict local checks, and reports whether the expected outcome and write
boundary were satisfied.

RunReconcile does **not** run the automation. There is intentionally no command,
shell, hook, plugin, scheduler, network client, or telemetry path in the tool.

> Status: `0.1.1` is an early release. Review the threat model and keep baseline
> snapshots private before using it in a sensitive workflow.

## Why this exists

An exit code or a successful log line does not prove that the intended artifact
exists, that a delivery receipt belongs to this run, or that nothing outside the
declared write surface changed. RunReconcile separates those questions from the
automation itself:

1. `snapshot` records the declared filesystem state and a caller-supplied run
   ID before execution, then prints the baseline's SHA-256.
2. You run the automation with your existing runner, CI system, cron service,
   or shell.
3. `verify` requires the independently retained baseline SHA-256, takes a fresh
   final-state snapshot, reconciles changes and checks, and publishes
   `receipt.json`, `receipt.md`, and a completion marker without replacing an
   existing output directory.

The receipt reports evidence about the two observed states. It does not claim
that a particular process caused a change or that no transient write occurred
between snapshots.

## Install

RunReconcile 0.1.x requires Python 3.9–3.14 on Linux or macOS. This first
release relies on POSIX descriptor-relative filesystem operations so that path
components cannot be swapped after validation; Windows is not yet supported.

Install the latest tagged release directly from GitHub:

```console
python -m pip install "runreconcile @ git+https://github.com/chown8872-afk/runreconcile.git@v0.1.1"
```

For an isolated CLI install, use `pipx` with the same tagged source:

```console
pipx install "git+https://github.com/chown8872-afk/runreconcile.git@v0.1.1"
```

A tag-gated PyPI Trusted Publishing workflow is included. The PyPI project is
not yet published, so this README does not claim a PyPI install path.

For development from a checkout:

```console
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

## One-command local demo from a source checkout

From the repository checkout used for the development install above, run the
complete snapshot → local job → verify flow:

```console
./scripts/run_demo.sh
```

The script copies the demo into a temporary workspace, keeps the private
baseline outside the watched tree, requires an `ACCEPTED` receipt, verifies the
completion marker digest, and deletes the temporary data. Set
`RUNRECONCILE_DEMO_KEEP=1` to retain the demo workspace for inspection.

A generated, public-safe example is committed at
[`examples/public-safe-receipt/`](examples/public-safe-receipt/). It contains
only the three publishable receipt files; the private baseline is deliberately
excluded.

## Quick start by hand

The included demo is entirely local. Its “delivery” file is a mock receipt; it
does not contact a service.

```console
runreconcile validate --contract examples/runreconcile.toml
runreconcile snapshot \
  --contract examples/runreconcile.toml \
  --output .runreconcile/demo-before.json \
  --run-id demo-001

# Copy the 64-character "sha256" from the JSON line printed above.
export BASELINE_SHA256=PASTE_SHA256_HERE

# RunReconcile is idle here. This command represents your automation.
python examples/demo_job.py --run-id demo-001

runreconcile verify \
  --contract examples/runreconcile.toml \
  --before .runreconcile/demo-before.json \
  --before-sha256 "$BASELINE_SHA256" \
  --output-dir .runreconcile/demo-receipt
```

Require `.runreconcile/demo-receipt/complete.json` before consuming the output,
then inspect `receipt.json` for the machine-readable source of truth or
`receipt.md` for the public summary. Snapshot and receipt destinations must not
already exist; use new names for another run.

Keep the snapshot-produced digest separately from the baseline until
verification. Do not recompute it from the baseline immediately before
`verify`: that would not detect an attacker who changed the baseline. The demo's
environment variable is illustrative; a protected CI output or secret store is
more appropriate when tampering is in scope.

## Verdicts

Boundary violations take precedence over check results.

| Verdict | Meaning | `verify` exit code |
|---|---|---:|
| `ACCEPTED` | No unexpected final-state change was observed and every required check passed. | 0 |
| `FAILED` | At least one required check was conclusively not satisfied. | 1 |
| `BOUNDARY_VIOLATION` | At least one observed change was outside the declared allow patterns. | 1 |
| `INDETERMINATE` | A required check could not be evaluated reliably. | 3 |

Optional check failures remain visible in the receipt but do not determine the
verdict. Invalid contracts return exit code 2. Snapshot, verification, or
receipt-publication errors return exit code 3.

## The contract

A TOML contract declares only observation policy. It contains no executable
field. See [`examples/runreconcile.toml`](examples/runreconcile.toml) for a
working contract.

```toml
schema_version = "1"
project_id = "example-export"
public_label = "Example export"

[privacy]
profile = "public-safe"

[[watch]]
id = "workspace"
root = "."
allow = ["output/**"]
max_file_bytes = 1048576

[[checks]]
id = "result"
type = "artifact"
public_label = "result artifact exists"
path = "output/result.json"
kind = "file"
changed_since_snapshot = true
```

Watch roots and check paths are relative to the directory containing the
contract. A watch root must exist, must be a directory, must stay inside that
directory, and must not be a symlink. Watch roots may not overlap, and every
check path must be below exactly one watch root.

`validate` rejects unknown fields, duplicate IDs, overlapping watch roots,
uncovered or ambiguously covered checks, malformed RFC 6901 pointers, and
inverted artifact bounds such as `min_bytes > max_bytes`. It also validates the
expected-value shape for operations that require a number, JSON type name,
array, or non-negative length.

Allow patterns classify observed changes, not files to scan. RunReconcile scans
the complete watch root and marks changed entries outside `allow` as unexpected.
Patterns are path-segment based: `*` and `?` match within one segment, while
`**` must occupy a complete segment and may span segments. Character classes
such as `[abc]` are deliberately unsupported.

### Check types

| Type | Purpose | Public evidence |
|---|---|---|
| `artifact` | Require a file or directory; files can add a size range, content change, or SHA-256 match. | Kind, file size, and an opt-in file digest. |
| `json` | Apply a strict RFC 6901 JSON Pointer assertion, optionally to content changed since baseline. | Whether the assertion was evaluated, never the raw value. |
| `delivery` | Require a content-new receipt, then correlate run ID, accepted status, and a non-empty provider receipt ID. | Boolean presence/acceptance signals, never the receipt ID. |

JSON documents must be UTF-8, reject duplicate keys and non-standard numbers,
and support these operations: `exists`, `absent`, `eq`, `ne`, `gt`, `gte`,
`lt`, `lte`, `type`, `in`, `contains`, and `length_eq`. Equality is type-strict,
so JSON `true` is not equal to `1`.

For all three check types, `changed_since_snapshot = true` requires creation,
type replacement, or a different content digest. A timestamp, permission, or
other metadata-only change does not satisfy freshness. Delivery checks enable
this requirement by default; artifact and JSON checks do not. For an existing
directory artifact, descendant changes do not make the directory entry fresh;
only creation or type replacement can satisfy that directory freshness check.

Explicit run IDs must match `[A-Za-z0-9._-]{1,128}`. If omitted, `snapshot`
generates a UUID. `verify` uses the run ID bound into the checked baseline.

## Boundary and coverage semantics

RunReconcile fingerprints regular files with SHA-256 and records entry kind,
size, modification time, and mode. It records a hash of a symlink target string
without following the link. Directory descent and artifact reads are anchored
to validated directory descriptors with no-follow semantics, and the complete
directory binding is revalidated before acceptance. Each watch must produce two
identical consecutive scans; oversized, growing, or unstable files and
inconsistent scans fail instead of being silently accepted. A watch is also
bounded to 100,000 entries, 64 directory levels, and 1 GiB of declared file
sizes per scan.

The boundary is a **final-state boundary**:

- Created, deleted, content-modified, and type-changed entries are reconciled;
  metadata-only changes are reported for files and symlinks.
- Directory permission-mode changes are reconciled. Directory modification
  time alone is ignored because ordinary descendant updates change it.
- A file changed and restored between snapshots is invisible.
- Writes are not attributed to a process.
- Changes outside declared watch roots are out of scope.
- Matching consecutive scans reduce cross-file inconsistency but are not an
  operating-system transaction; mutation before, after, or carefully across the
  paired observation remains outside a global atomic-snapshot guarantee.

An `ACCEPTED` verdict means the declared final-state contract was satisfied at
observation time. It is not a sandbox escape verdict, malware scan, proof of
causality, or guarantee that the automation was correct in every unobserved
respect.

## Public-safe receipts

`verify` reserves a new directory and writes:

- `receipt.json`: machine-readable receipt and source of truth.
- `receipt.md`: human-readable rendering with the JSON receipt hash.
- `complete.json`: written last; declares completion and repeats the JSON
  receipt SHA-256 for consumers.

Consumers should ignore a directory without `complete.json` and should compare
its `receipt_json_sha256` with the bytes of `receipt.json`. The marker detects an
incomplete or modified publication; it is not a digital signature.

Receipts omit raw asserted JSON values, absolute paths, unexpected path names,
and delivery receipt IDs. They include contract-authored project IDs, check IDs,
public labels, the run ID, timestamps, counts, result codes, and selected safe
evidence. If `record_sha256 = true`, the artifact digest is intentionally
public too. Only use public-safe text in contract IDs and labels.

The **baseline snapshot is not a public artifact**. It contains relative entry
names, metadata, and hashes. Keep it in access-controlled storage and do not
attach it to a public issue or release. CLI diagnostics are also outside the
public-receipt privacy guarantee.

See [`PRIVACY.md`](PRIVACY.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md) before
publishing receipts from a sensitive workflow.

## How it differs from adjacent tools

- **Workflow runners and schedulers** execute commands, manage retries, and own
  lifecycle. RunReconcile intentionally does none of those things and can sit
  after any runner.
- **Test frameworks** exercise code and usually trust the test process.
  RunReconcile independently observes declared artifacts and write boundaries.
- **Filesystem watchers, audit systems, and sandboxes** can trace runtime events
  or enforce access. RunReconcile performs portable point-in-time comparison and
  makes no process-attribution claim.
- **Checksum or directory-diff utilities** expose raw paths and changes.
  RunReconcile adds a strict outcome contract, verdict semantics, and a
  deliberately minimized public receipt.

## Development

The runtime uses only the Python standard library on Python 3.11+ and `tomli`
for TOML parsing on Python 3.9–3.10.

```console
python -m pip install -e .
python -m unittest discover -s tests -v
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for invariants and the pull request
checklist, [`ROADMAP.md`](ROADMAP.md) for planned work, and
[`GOVERNANCE.md`](GOVERNANCE.md) for the public maintenance process. Security
reports belong in the private channel described in [`SECURITY.md`](SECURITY.md).

## License

RunReconcile is available under the [MIT License](LICENSE).
