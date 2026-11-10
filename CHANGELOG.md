# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Implemented the Rust half of protocol Task 3.3: exact six-byte interactive SAS derivation using the transcript's
  SHA-256 digest as HKDF-SHA-256 salt, `reporter_nonce || core_nonce` input, fixed profile info, and six-byte output;
  exact alternating Even/Odd rendering; strict bounded six-word ASCII parsing; and constant-time authentication-byte
  verification. A hash-pinned `SasWordLists` loader accepts caller-provided resources so the MIT production library
  embeds no GFDL data, and the demonstration bounds each resource read before allocation and validation. Tests load the
  exact server-owned 256-entry tables from the vendored profile and cover every index in every position, known PGP
  examples, the merged interactive vector, boundaries, and word/list/case/punctuation/spacing mutations. The vendored
  profile now includes the adjacent attribution notice and full GFDL 1.2 license. Rust code, tests, examples, and
  ordinary documentation remain MIT; only the Even/Odd data files and any byte-identical copies are GFDL-1.2-only.
  Added exact-pinned, default-feature-free `hkdf` 0.13.0 for the fixed HKDF operation.

- Added a draft `protocol_v1` library module for the server-owned REM protocol v1 profile, vendored byte-for-byte with
  pinned checksums. **The profile is not approved for distribution and awaits independent security review; nothing
  listens on or sends the protocol, and the reporter executable is unchanged.** The module provides strict canonical
  base64url with constant-time value equality, the bounded `REM-TRANSCRIPT` encoding and exact ordered decoder, exact
  canonical JSON checks, exact canonical P-256 public JWKs with
  on-curve validation and RFC 7638 thumbprints, the single-member RFC 9530 `sha-256` `Content-Digest` with
  constant-time verification, 64-byte P1363 low-S ECDSA P-256 verification, manifest-driven route lookup that validates
  exact methods, targets, and query forms, and narrow `reporter-rfc9421-v1`/`control-rfc9421-v1` request admission in
  the profile's order. Request admission validates canonical IDNA2008 A-label authorities, including numeric-address and
  reserved-LDH rejection, and includes dispatcher-selected route binding, the dual `rem`/`rem-proposed` route,
  server-receipt-time control freshness, and a stable principal plus exact request/hash for later replay and exact-retry
  handling. `RawRequest` already contains a fully buffered body, so the library body-cap check is defense in depth. Any
  later executable HTTP transport integration must count body bytes and abort oversized requests while streaming, before
  allocating or buffering the full body. Schema semantics remain separately deferred. Stateful replay protection and
  later executable integration are not included. Tests pin the corpus file set, checksums, and counts; re-encode every
  published bounded transcript; execute all six structural transcript mutations; accept every published canonical JSON
  value; verify the JWK- and SPKI-backed transcript signatures and their altered and high-S rejection cases; reproduce
  all 25 HTTP signature cases and identities; and execute all 506 in-scope HTTP one-field mutations plus the dual-key
  rotation case with their declared failures, including both singleton snapshot duplicate-query-member mutations. This
  does not claim MQTT, managed-token HMAC, schema, or stateful-replay conformance. Reporter signatures and identities
  omit client `created` entirely while control `created`/`expires`/`nonce` freshness remains bound to server receipt time. A
  demonstration example generates an ephemeral in-memory key, self-verifies, and emits a closed canonical JSON object
  containing only public verification material and exact request bytes for a server Python verifier; persistent
  reporter keys must use the System Keychain. Task 3.4's
  independent security review must approve the profile and implementation before distribution. New exact-pinned,
  feature-minimized runtime dependencies: `idna` 1.1.0 (`alloc`, `compiled_data`), `p256` 0.14.0 (`ecdsa`), `sha2`
  0.11.1, and `subtle` 2.6.1.
- Added the foreground Apple-silicon telemetry spike: a direct, ownership-safe IOKit reader for selected
  `AppleSmartBattery.PowerTelemetryData` integers and source-owned accumulators; a public IOPowerSources reader that
  uses `Type` and `Is Present` only to require exactly one present `InternalBattery`, fails closed if none or multiple
  match, and does not emit either selection field. Its CSV public-source columns contain power mode, charging, optional
  battery voltage/current, and derived terminal-power values; bounded CLI sampling and privacy-safe raw CSV are also
  included. Each candidate is now acquired inside a monotonic public/private/public state bracket of no more than one
  second, requires matching classifiable modes, and receives mode-specific candidate, hard-ceiling, mandatory
  `SystemPowerIn = SystemLoad + BatteryPower`, exact 1%-with-1-mW-floor, AC input, and battery
  negative-power/magnitude checks. Apple ARM compilation runs in CI, and the physical-laptop probe remains explicitly
  ignored. One bracketed five-minute idle, CPU-load, and GPU-load run in each mode passed on the tested Apple-silicon
  laptop, including per-counter freshness, accumulator signs/bounds/direction, battery signed-inverse intervals,
  transition fail-closed behavior, and resource limits. The spike remains separate from `PowerSource` until production
  source-loss, freshness, transition, and signed-unavailable behavior is implemented. Physical power meters remain
  outside project scope and are not required.
- Established the `0.0.1` measurement-qualification baseline. The reporter has no installable or persistent service and
  exits with `WHOLE_SYSTEM_UNAVAILABLE` until code-only evidence qualifies Apple-reported system power. The source is
  documented as undocumented, not externally calibrated or billing-grade, and unsuitable for billing, settlement, or
  safety-critical decisions.
- Added fail-closed publication policy for staged changes, commit messages, pushed refs and Git objects, full repository
  history, local-setup references, dependencies, branch routing, and the six required CI checks. Publication scans use
  pinned tools, bounded private streams, and verified CI downloads.

### Changed

- Limited each foreground telemetry spike to a ten-hour scheduled sampling span while retaining the individual sample
  count and interval ranges needed for five-minute qualification runs.
- Batched and deduplicated pre-push and CI Git-object publication scans while retaining complete fail-closed object
  and resource-limit checks. Publication scans now accept both SHA-1 and SHA-256 Git object IDs, reject malformed or
  mixed-width IDs, and fail closed on missing, duplicate, malformed, or unsupported annotated-tag target headers.
