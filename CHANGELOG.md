# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
