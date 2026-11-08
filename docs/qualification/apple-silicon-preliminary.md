# Apple-silicon candidate telemetry — preliminary result

## Status

**Promising but not qualified.** The production `PowerSource` remains fail-closed. Apple-silicon AC support still
requires a synchronized external wall-meter comparison. Battery support qualifies independently; if it does not
qualify, battery must remain unsupported with evidence that the future signed reporter transitions immediately to
`WHOLE_SYSTEM_UNAVAILABLE` and repeats that state at the normal report cadence. An unsupported battery mode does not
block AC-only support.

This report contains aggregate results only. Raw captures remain in the gitignored `spike-data/` directory and contain
no machine identity fields.

## Method

A release build of the foreground Rust spike read selected integer values directly from the
`AppleSmartBattery.PowerTelemetryData` IORegistry property once per second for five minutes under each AC-powered
condition. The reader uses public IOKit registry functions, but the property and field names are undocumented by Apple.

- Idle: ordinary foreground use, no intentional load.
- CPU: all logical CPUs kept busy.
- GPU: sustained Metal compute workload.
- Candidate watts: `SystemLoad / 1000` (hypothesized milliwatts).
- Independently calculated V×I value: `SystemVoltageIn × SystemCurrentIn / 1,000,000` (hypothesized mV × mA → W).
  The collector records this value but does not validate agreement with `SystemPowerIn`.
- Reporter CPU: process user+system CPU time divided by wall duration, expressed as one-core percentage.
- Memory: maximum resident set size.

No external wall-meter value was available during these runs, so accuracy relative to real AC input was not evaluated.
`powermetrics` was not treated as whole-system ground truth.

## Aggregate observations

| Condition | Samples / elapsed | Mean candidate | Range | Distinct values | Max V×I difference | Reporter CPU | Max RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Idle AC | 300 / 300.8 s | 3.581 W | 3.392–4.281 W | 6 | 0.556% | 0.0233% | 5.86 MiB |
| CPU AC | 300 / 301.3 s | 35.486 W | 4.281–39.656 W | 6 | 0.077% | 0.0066% | 5.88 MiB |
| GPU AC | 300 / 301.2 s | 69.250 W | 4.600–79.317 W | 6 | 0.252% | 0.0066% | 5.84 MiB |

The voltage/current calculation agrees closely with `SystemPowerIn`, supporting the millivolt/milliamp/milliwatt unit
hypothesis. The candidate responds strongly and directionally to CPU and GPU load. Reporter overhead passes the
provisional `<0.5%` of one core and `<30 MiB` limits.

The underlying value updates roughly once per minute after the initial load transition, despite one-second reads. A
30-second reporter would therefore often send an unchanged measurement. Qualification must decide whether this update
cadence is adequate for ±10% five-minute energy means; the production implementation must not mistake an unchanged
value for a fresh hardware update.

## Remaining qualification gates

1. Repeat idle/CPU/GPU AC runs with a synchronized external wall-power meter. For each run, the unadjusted candidate
   five-minute mean must be within ±10% of the unadjusted synchronized wall-meter mean; do not apply post-hoc offsets,
   scaling, or boundary adjustments.
2. Resolve battery mode independently through one of these outcomes:
   - qualify battery support by running the same idle/CPU/GPU matrix against a predeclared credible independent power
     or energy reference, with every unadjusted five-minute mean within ±10% of that reference; or
   - declare battery unsupported and verify that entry into battery mode makes the future signed reporter emit
     `WHOLE_SYSTEM_UNAVAILABLE` immediately and repeat it at the normal report cadence.
3. Record the telemetry property's real update timestamps or accumulated counters so freshness is based on source
   updates, not read attempts.
4. Run the same probe on the available Intel Mac. Absence or inaccuracy leaves Intel unsupported and does not block a
   separately qualified Apple-silicon AC mode.
5. Re-run on at least one additional Apple-silicon laptop model before calling the source generally supported.

Until the required gates for a claimed mode pass, `cargo run` continues to return `WHOLE_SYSTEM_UNAVAILABLE`; only the
explicit `spike` command can read these candidate values. Battery qualification is not a prerequisite for an AC-only
support claim when the signed-unavailable transition and cadence evidence pass.
