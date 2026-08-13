# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-08-13

### Added

- End-to-end packaged demo validation and distribution checks in CI.
- Python 3.13 and 3.14 compatibility coverage.
- Reproducible local demo script and generated public-safe example receipt.
- Roadmap, governance notes, issue forms, pull request template, CodeQL
  analysis, Dependabot configuration, and a tag-gated trusted-publishing
  workflow for PyPI.
- Complete package ownership and project-link metadata.

### Changed

- Updated the README with status badges, a clearer post-run verifier
  positioning, install paths, and a one-command demo.
- Expanded the source distribution to include examples, security documents,
  the roadmap, governance notes, and the demo script.

## [0.1.0] - 2026-08-13

### Added

- Strict, non-executable TOML contract schema version 1 with load-time pointer,
  size-bound, watch-overlap, and exact check-coverage validation.
- Two-phase `snapshot` and `verify` workflow with contract-hash, run-ID, and
  caller-retained baseline-digest binding.
- Final-state filesystem reconciliation with explicit allow patterns, stable
  double-scan SHA-256 fingerprinting, hard size limits, directory-mode evidence,
  non-followed symlinks, descriptor-relative no-follow traversal, final path
  rebinding checks, and fixed depth/entry/total-size ceilings.
- Artifact, strict JSON Pointer, and run-correlated delivery checks whose
  freshness rules require content changes rather than metadata touches.
- `ACCEPTED`, `FAILED`, `BOUNDARY_VIOLATION`, and `INDETERMINATE` verdicts.
- Public-safe JSON and Markdown receipts with an integrity-bound completion
  marker and no overwrite of existing receipt directories.
- Local-only runtime with no command execution, network access, or telemetry.
- Linux and macOS test workflow for Python 3.9–3.12.
