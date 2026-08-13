# Privacy

RunReconcile is designed for local, minimal-disclosure reconciliation. Version
0.1.x contains no network client, telemetry, analytics, advertising identifier,
account system, or remote service integration. It neither uploads data nor
checks for updates.

## Data processed locally

Depending on the contract, RunReconcile reads:

- the TOML contract;
- directory entry names and metadata under declared watch roots;
- regular-file bytes for SHA-256 fingerprinting;
- selected JSON artifacts for local assertions; and
- a private baseline snapshot supplied to `verify`.

JSON assertion values and delivery fields are evaluated in the local process.
They are not copied into the public receipt.

## Files created

| Output | Intended handling | Contents |
|---|---|---|
| Baseline snapshot | **Private** | Relative entry names, kinds, sizes, modes, timestamps, file hashes, hashed symlink target strings, run ID, and contract hash. |
| `receipt.json` | Public-safe after contract review | Verdict, public IDs and labels, run metadata, counts, result codes, coverage limits, contract hash, and selected minimized evidence. |
| `receipt.md` | Public-safe after contract review | Human-readable rendering of the JSON receipt plus its SHA-256. |
| `complete.json` | Public-safe completion marker | Completion flag and SHA-256 of the JSON receipt. |

RunReconcile does not manage retention or deletion. The operator chooses output
locations and lifecycle. Existing baseline files and receipt directories are
not overwritten.

## What “public-safe” means

The public receipt format omits:

- raw JSON values used by assertions;
- absolute filesystem paths;
- relative names of unexpectedly changed entries;
- delivery provider receipt IDs; and
- file content.

It intentionally includes:

- contract-authored `project_id`, `public_label`, check IDs, and check labels;
- the caller-provided run ID;
- start and finish timestamps and duration;
- contract and receipt hashes;
- check types, statuses, stable result codes, and counts;
- allowed and unexpected change counts; and
- file size and, when `record_sha256 = true`, the artifact SHA-256.

IDs, labels, and run IDs are not sanitized into anonymous identifiers. Do not
place customer names, ticket contents, email addresses, secrets, internal path
names, or other sensitive data in those fields. A digest of low-entropy or known
content may allow guessing; enable `record_sha256` only when the digest itself is
safe to publish.

Run IDs are restricted to 1–128 ASCII letters, digits, dots, underscores, and
hyphens, but those characters can still encode a sensitive identifier. The
baseline SHA-256 printed by `snapshot` should be retained separately for
tamper-checking; it does not contain raw baseline data.

The `public-safe` claim is limited to the three receipt-directory files.
Baselines are not public-safe. Contracts may contain sensitive operational structure. Runtime
snapshot and verification failures are generalized, but contract-validation and
other CLI output are not part of the receipt schema, so do not publish terminal
logs without review.

## Network and telemetry

RunReconcile performs zero network requests and emits zero telemetry. The demo
job also stays local; its delivery record is explicitly simulated. Package
installation tools may access package indexes, but that behavior belongs to the
installer, not the RunReconcile runtime.

## Operating-system traces

The host may independently retain command history, filesystem backups, endpoint
security logs, temporary storage, or CI logs. RunReconcile cannot control those
systems. Place private outputs on storage whose permissions, backup policy, and
retention meet your requirements.

## Publishing checklist

Before publishing a receipt:

1. Confirm that the contract's project ID, check IDs, and public labels are safe.
2. Confirm that the run ID is not sensitive.
3. Review opt-in artifact digests.
4. Require `complete.json` and verify its digest before consuming the receipt.
5. Publish only the three receipt-directory files, never the baseline.
6. Review any surrounding CI or terminal log separately.

For a security issue affecting these guarantees, follow [`SECURITY.md`](SECURITY.md).
