# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added the foreground Apple-silicon telemetry spike: a direct, ownership-safe IOKit reader for selected
  `AppleSmartBattery.PowerTelemetryData` integers, bounded CLI sampling, privacy-safe raw CSV, numeric-bound
  validation, a V×I cross-check calculation and test, Apple ARM compilation in CI, and an explicitly ignored
  physical-laptop probe. It remains separate from `PowerSource`; no value is reportable until external wall-meter
  qualification passes.
- Established the `0.0.1` measurement-qualification baseline. The reporter has no installable or persistent service and
  exits with `WHOLE_SYSTEM_UNAVAILABLE` until externally measured hardware evidence qualifies a whole-system power
  source.
- Added fail-closed publication policy for staged changes, commit messages, pushed refs and Git objects, full repository
  history, local-setup references, dependencies, branch routing, and the six required CI checks. Publication scans use
  pinned tools, bounded private streams, and verified CI downloads.

### Changed

- Limited each foreground telemetry spike to a ten-hour scheduled sampling span while retaining the individual sample
  count and interval ranges needed for five-minute qualification runs.
- Batched and deduplicated pre-push and CI Git-object publication scans while retaining complete fail-closed object
  and resource-limit checks. Publication scans now accept both SHA-1 and SHA-256 Git object IDs, reject malformed or
  mixed-width IDs, and fail closed on missing, duplicate, malformed, or unsupported annotated-tag target headers.
