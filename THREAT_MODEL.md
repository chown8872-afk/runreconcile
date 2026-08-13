# Threat model

This document describes the security claims and non-claims of RunReconcile
0.1.x. It should be read together with the privacy documentation.

## System model

RunReconcile has two observation phases around an automation it does not
control:

```text
trusted contract -> snapshot -> external automation -> verify -> public receipt
                         |             retained digest   |
                    private baseline  ----------------> fresh snapshot + checks
```

The contract directory is the containment boundary for watch roots and check
paths. The baseline binds a run ID and the SHA-256 of the exact contract bytes.
`snapshot` prints the SHA-256 of the exact baseline bytes, and `verify` requires
that digest before parsing the baseline. Verification also refuses a baseline
whose embedded contract hash differs from the current contract.

## Assets

- Integrity of the verdict and check result codes.
- Confidentiality of raw JSON values, delivery receipt IDs, absolute paths, and
  unexpected path names in the public receipt.
- Integrity and completeness of the declared final-state observation.
- Availability of the verifier when inspecting malformed or changing data.
- The private baseline snapshot, which contains relative names, metadata, and
  hashes and is not designed for publication.

## Trust assumptions

The operator is responsible for:

- obtaining RunReconcile and its Python environment through a trusted channel;
- supplying a reviewed contract whose IDs and public labels are safe to publish;
- protecting the contract and baseline from unauthorized modification;
- retaining the snapshot-produced baseline digest separately from the baseline
  when tampering is in scope;
- choosing watch roots broad enough to cover the intended write boundary;
- running `snapshot` before, and `verify` after, the relevant automation;
- preventing or accounting for unrelated concurrent writers; and
- publishing only the receipt files, not the baseline or unreviewed terminal
  diagnostics.

The automation under observation may fail, produce malformed files, or write
outside its declared allowance. It is not trusted to report its own success.
The host operating system, Python interpreter, filesystem implementation, and
the account running RunReconcile are trusted.

Contracts are policy, not untrusted input to be hosted as a service. A malicious
contract author controls receipt IDs and labels and can choose a broad in-scope
directory, creating confidentiality and availability risk for the operator even
though the contract cannot contain a command.

## Security properties

### No execution or network authority

The contract schema has no command or hook field. RunReconcile does not spawn
processes, import user modules, make network requests, or send telemetry. The
external automation is launched separately by the operator's existing runner.

### Path containment

Contract paths must be relative and cannot contain parent traversal. Watch roots
must resolve inside the contract directory, may not overlap, and may not be
symlinks. Every check must be covered by exactly one watch. Check paths reject
symlink components. Snapshot traversal records symlinks without following them.
Directory descent and checked-file reads use descriptor-relative no-follow
operations, keep the validated directory chain open, and revalidate every path
binding after use. Version 0.1.x requires POSIX support for these operations and
fails validation on unsupported platforms.

Contract validation also rejects malformed JSON Pointers, ambiguous check
coverage, and internally inconsistent artifact size bounds before observation
begins.

These controls defend against accidental or contract-directed traversal outside
the contract directory. They are not an operating-system sandbox for the
external automation.

### Fail-closed observation

Regular files are read through a descriptor with a hard byte ceiling, hashed,
and checked for stable identity, path binding, size, modification time, and
mode. Directory artifacts are reopened and rebound to their final snapshot
entry before a check can pass. Each watch must produce two identical consecutive
scans and has fixed ceilings of 100,000 entries, 64 directory levels, and 1 GiB
of declared file sizes. Oversized or growing files, unsupported entry types,
unreadable directories, and unstable artifacts or trees cause an error instead
of silent omission. JSON parsing rejects duplicate keys and non-standard
numbers.

The paired directory walks reduce cross-file inconsistency but are not a global
filesystem transaction. A mutation can still occur outside the pair or be timed
so both observations match; this is a stated coverage limitation rather than a
process-tracing guarantee.

### Baseline binding and output publication

The baseline contains the run ID and contract digest. Snapshot creation returns
an external SHA-256 of the serialized baseline; verification requires an exact
match before loading it. Verification then creates a fresh snapshot with the
same run ID and requires both snapshots to match the current contract. Snapshot
files are written to a temporary file and linked into the final name with
no-replace semantics. Receipt publication exclusively reserves the final
directory and files, then writes `complete.json` last with the JSON receipt
digest. Existing snapshot paths and receipt directories are not overwritten.

The external digest detects baseline tampering only if it is retained through a
separate trusted channel. Recomputing the expected digest from an untrusted
baseline, or storing both under identical write authority, defeats that check.

Consumers must require `complete.json` and verify its JSON digest before using a
receipt directory. The completion marker handles visible partial publication;
it does not make the three-file write a transaction. Receipt hashes provide
integrity evidence, not authenticity: receipts are not digitally signed.

### Public receipt minimization

Public receipts contain counts and contract-authored labels rather than observed
path names or raw asserted values. Delivery checks reveal only that the run ID,
status, and receipt-ID presence tests passed. An artifact digest is included only
when requested with `record_sha256 = true`. Markdown-authored values are escaped
before rendering.

This property applies to `receipt.json`, `receipt.md`, and `complete.json`. It
does not apply to the baseline, the contract itself, shell history, or CLI
diagnostics.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Contract escapes its directory | Relative-path validation, resolution containment, symlink-root rejection | A trusted operator can still choose `.` and intentionally scan the whole contract tree. |
| Symlink exposes an external target | Symlinks are not followed; directory descent and check reads use no-follow descriptor-relative operations | The private baseline can include a symlink's relative name and a hash of its target string. |
| File or tree changes while scanned | Descriptor identity checks, hard read ceiling, and two identical consecutive scans | No global filesystem transaction covers the complete tree. |
| Oversized input is silently omitted | Per-file and fixed per-watch depth, entry-count, and total-size ceilings fail the snapshot | A broad tree can still consume time and baseline space within those ceilings. |
| Malformed JSON creates ambiguous assertions | UTF-8, duplicate-key rejection, strict JSON numbers, type-strict equality | Application-level semantics remain the contract author's responsibility. |
| Metadata touch masquerades as fresh evidence | Artifact, JSON, and delivery freshness require a new entry, type replacement, or changed content digest | The producer can still rewrite equivalent semantics with different bytes. |
| A stale delivery receipt is reused | Delivery checks default to requiring a content change and must match the baseline run ID; touching metadata is insufficient | The producer of the local delivery file can lie; provider signatures are not verified. |
| Baseline is modified before verification | `verify` requires the SHA-256 emitted by `snapshot` | An attacker who can replace both baseline and retained digest can bypass this binding. |
| Unexpected filename leaks publicly | Receipt exposes only unexpected-change counts; snapshot/verify runtime errors are generalized | Baselines and contract-validation diagnostics remain private. |
| Receipt is partial or modified after creation | A completion marker is written last and includes the JSON receipt SHA-256 | No signature or trusted timestamp establishes authorship; consumers must enforce the marker check. |
| Automation writes and restores a forbidden file | None in final-state mode | Transient writes are outside the model; use OS auditing or sandboxing when required. |
| Unrelated process changes a watched file | The change is detected if present in the final state | RunReconcile cannot identify which process caused it. |

## Explicit non-goals

RunReconcile is not:

- a sandbox, mandatory access-control system, antivirus scanner, or secret
  scanner;
- a runtime filesystem monitor or syscall audit log;
- a workflow engine or command runner;
- proof that a specific process caused the observed final state;
- proof that no transient or out-of-scope write happened;
- protection against privileged mount-namespace or kernel-level manipulation;
- a signed attestation system; or
- a substitute for provider-side verification of an external delivery.

## Recommended deployment

1. Place the contract at the narrowest practical common parent of watched data.
2. Use narrow watch roots and allow patterns; avoid broad roots containing
   secrets or unrelated high-churn files.
3. Set realistic `max_file_bytes` limits and run with the least filesystem
   privilege needed for observation.
4. Store the baseline in private, access-controlled storage and use a unique run
   ID and output path per run.
5. Quiesce unrelated writers where possible.
6. Review contract IDs, labels, and any opt-in digests before publishing a
   receipt.
7. Require the completion marker and verify its JSON digest before consuming a
   receipt directory.
8. Use an OS sandbox or audit facility in addition to RunReconcile when
   transient-write prevention or causal attribution matters.

Please report implementation weaknesses through the private process in
[`SECURITY.md`](SECURITY.md).
