# Security and privacy — MANDATORY

> Security is priority #1. Choose the more restrictive option when uncertain and surface the trade-off.

This repository is public and the reporter will run as a privileged daemon on machines outside any trusted perimeter.
Treat every commit and release artifact as publication.

## Zero trust

- LAN, VPN, loopback, mDNS/DNS-SD, broker, Home Assistant internal networks, and proximity grant no trust.
- Authenticate every server and reporter independently; authorize each operation and bind identity to its resource.
- Discovery is a routing hint only. First contact requires a verified SAS or an MDM-provisioned pin/token.
- TLS 1.3 and request signatures are independent controls. Never add a plaintext/insecure-skip mode.
- Strictly cap/validate all input before allocation or cryptographic work; enforce replay, freshness, rate, concurrency,
  and capacity limits server-side.
- Assume a reporter can be compromised; one identity must not affect another. Never use shared fleet credentials.

## Keys and signing

- Reporter identity is a client-generated P-256 key. Persistent macOS installation uses a non-exportable System
  Keychain key and Developer ID-signed/notarized daemon/application. Unsigned code is foreground spike-only.
- Never log/export/transmit private keys, enrollment tokens, local machine identifiers, raw spike captures, or signing
  credentials. CI signing credentials use protected environments and least privilege.
- No self-updater. Installation/update is explicit or MDM-driven.

## Measurement integrity and privacy

- Security and privacy take priority over qualification progress. Fail closed rather than accepting incomplete,
  ambiguous, stale, cross-mode, or unreviewed evidence.
- Publish Apple-reported system power only after the candidate mode independently passes one five-minute idle,
  CPU-load, and GPU-load run under the documented public/private/public bracket, direct consistency, per-counter
  freshness, accumulator sign/bounds/direction, matching battery signed-inverse, workload-median, transition, and
  resource criteria. Never relabel CPU/GPU/package values.
- Each bracket must use monotonic public-before/private/public-after boundaries in nondecreasing order, complete in no
  more than one second, and have matching classifiable modes in both public reads. A mode change or invalid bracket
  fails closed.
- Every selected mode candidate must be finite, greater than zero, and no more than 100 kW. Every accepted snapshot
  must satisfy `SystemPowerIn = SystemLoad + BatteryPower` under the exact milliwatt comparison
  `abs(a - b) <= max(1 mW, 0.01 * max(abs(a), abs(b)))`. Battery mode additionally requires negative
  `BatteryPower` whose magnitude matches `SystemLoad` under that rule.
- Enforce freshness separately for every mandatory mode-specific counter. A zero delta is valid only before the
  half-open 90-second deadline measured from the initial observation or latest positive delta; exactly 90 seconds is
  stale. An advance by one counter does not refresh another. A positive count delta closes a source-owned accumulator
  interval whose mean must be finite, correctly signed, bounded, and directionally consistent; matching battery
  load/discharge intervals must be signed inverses. Do not assign repeated process reads to hidden source intervals.
- State that code-only qualification does not establish physical accuracy. Never call the source externally calibrated
  or billing-grade, and never recommend it for billing, settlement, or safety-critical decisions. Physical power
  meters are outside this project's scope and are not a qualification requirement.
- Fail closed with `WHOLE_SYSTEM_UNAVAILABLE` when the source is missing, stale, invalid, or unqualified.
- Never transmit hardware serial/UUID, username/account, MAC, or client wall-clock timestamp.
- Store every raw capture in the repository-root `./spike-data/` directory. Only that directory is covered by the
  raw-capture ignore rule; a capture elsewhere is not protected and must not be created, staged, or committed.
- Only a reviewed, UTF-8 text aggregate report with neutral labels and no raw samples or local setup details may be
  exported from `./spike-data/` and committed. Keep the source capture in `./spike-data/`.

## Supply chain

- Pin Rust/tool versions and GitHub Actions immutably; commit `Cargo.lock`.
- `cargo audit` and `cargo deny check advisories bans licenses sources` block advisories, yanked crates, unapproved
  licenses/sources, and wildcards.
- Gitleaks scans staged changes in pre-commit, and the `commit-msg` hook scans each pending commit message. Pre-push
  privately scans bounded local and remote ref-name streams and complete pushed Git object payloads, including blob
  contents, tree records, commit/tag headers and messages, and tags whose final targets are blobs or trees. The
  publication scanners accept 40-hex SHA-1 and 64-hex SHA-256 object IDs, reject malformed or mixed-width IDs, and fail
  closed on missing, duplicate, malformed, or unsupported annotated-tag target headers. Commit targets receive one
  combined Gitleaks history scan. Overlapping pushed ranges and objects are deduplicated, and one persistent Git reader
  feeds one bounded Gitleaks object stream with explicit newline boundaries between complete objects. CI scans full Git
  history, then privately scans bounded streams containing all fetched and triggering ref names and every fetched Git
  object payload, including non-commit tag targets. Output from private-stream scans is suppressed so rejected metadata
  does not enter diagnostics. CI manually verifies the pinned Gitleaks release archive checksum and reported version
  before execution.
- Pre-commit requires exact versions of Gitleaks `8.30.1`, cargo-audit `0.22.2`, and cargo-deny `0.20.2`. The
  `commit-msg` and pre-push hooks require exact Gitleaks `8.30.1` only. CI installs the configured cargo-audit and
  cargo-deny versions and runs the version-check self-tests for all three hooks.
- The local-reference scanner checks staged and tracked path names and text, pending commit messages, pushed local and
  remote ref names, and historical commit/tag metadata, path names, and text blobs. It rejects unsupported binary,
  non-UTF-8, and oversized artifacts rather than allowing content it cannot inspect. Never weaken or bypass either
  publication gate.
